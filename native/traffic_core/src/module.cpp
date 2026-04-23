#include <pybind11/pybind11.h>
#include <pybind11/stl.h>

#include <algorithm>
#include <array>
#include <cctype>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <fstream>
#include <iomanip>
#include <optional>
#include <sstream>
#include <stdexcept>
#include <string>
#include <vector>

namespace py = pybind11;

namespace {

enum class FileFormat { kUnknown = 0, kPcap = 1, kPcapNg = 2 };

struct PacketRow {
    double ts{0.0};
    std::string src_ip;
    std::string dst_ip;
    std::int64_t src_port{0};
    std::int64_t dst_port{0};
    std::string proto;
    std::int64_t length{0};
    std::string direction{"offline"};
    std::int64_t process_id{0};
    std::string process_name{"offline"};
    std::string raw_hex;
    std::int64_t tcp_flags_mask{0};
    std::string payload_preview;
    std::string http_method;
    std::string http_url;
    std::string http_host;
    std::int64_t http_status{0};
    std::string dns_query;
    std::int64_t dns_qtype{0};
    std::string dns_answer;
    std::string tls_sni;
    std::string tls_cipher;
    std::int64_t ip_version{0};
    std::int64_t ip_ttl{0};
    std::int64_t ip_frag_offset{0};
    std::int64_t ip_more_frag{0};
};

[[noreturn]] void fail(const std::string& code, const std::string& msg) {
    throw std::runtime_error(code + ": " + msg);
}

bool read_exact(std::istream& in, char* buffer, std::size_t len) {
    in.read(buffer, static_cast<std::streamsize>(len));
    return static_cast<std::size_t>(in.gcount()) == len;
}

std::uint16_t read_u16(const std::uint8_t* p, bool little_endian) {
    if (little_endian) {
        return static_cast<std::uint16_t>(p[0] | (static_cast<std::uint16_t>(p[1]) << 8));
    }
    return static_cast<std::uint16_t>((static_cast<std::uint16_t>(p[0]) << 8) | p[1]);
}

std::uint32_t read_u32(const std::uint8_t* p, bool little_endian) {
    if (little_endian) {
        return static_cast<std::uint32_t>(p[0]) | (static_cast<std::uint32_t>(p[1]) << 8) |
               (static_cast<std::uint32_t>(p[2]) << 16) | (static_cast<std::uint32_t>(p[3]) << 24);
    }
    return (static_cast<std::uint32_t>(p[0]) << 24) | (static_cast<std::uint32_t>(p[1]) << 16) |
           (static_cast<std::uint32_t>(p[2]) << 8) | static_cast<std::uint32_t>(p[3]);
}

std::string to_ipv4(const std::uint8_t* p) {
    std::ostringstream ss;
    ss << static_cast<int>(p[0]) << "." << static_cast<int>(p[1]) << "." << static_cast<int>(p[2]) << "." << static_cast<int>(p[3]);
    return ss.str();
}

std::string to_ipv6(const std::uint8_t* p) {
    std::ostringstream ss;
    ss << std::hex << std::nouppercase;
    for (int i = 0; i < 8; ++i) {
        const std::uint16_t group = static_cast<std::uint16_t>((p[i * 2] << 8) | p[i * 2 + 1]);
        ss << group;
        if (i < 7) {
            ss << ":";
        }
    }
    return ss.str();
}

std::string bytes_to_hex(const std::uint8_t* data, std::size_t len) {
    std::ostringstream ss;
    ss << std::hex << std::nouppercase << std::setfill('0');
    for (std::size_t i = 0; i < len; ++i) {
        ss << std::setw(2) << static_cast<unsigned>(data[i]);
    }
    return ss.str();
}

std::string lower_ascii_preview(const std::uint8_t* data, std::size_t len, std::size_t max_len = 256) {
    const std::size_t take = std::min(len, max_len);
    std::string out;
    out.reserve(take);
    for (std::size_t i = 0; i < take; ++i) {
        unsigned char ch = data[i];
        if (ch < 32 || ch > 126) {
            continue;
        }
        out.push_back(static_cast<char>(std::tolower(ch)));
    }
    return out;
}

bool starts_with(const std::string& text, const std::string& prefix) {
    return text.size() >= prefix.size() && text.compare(0, prefix.size(), prefix) == 0;
}

std::size_t dns_read_name(const std::vector<std::uint8_t>& payload, std::size_t offset, std::string& out_name) {
    out_name.clear();
    std::size_t consumed = 0;
    std::size_t cursor = offset;
    int jumps = 0;
    bool jumped = false;
    while (cursor < payload.size()) {
        const std::uint8_t len = payload[cursor];
        if ((len & 0xC0) == 0xC0) {
            if (cursor + 1 >= payload.size()) {
                return 0;
            }
            const std::uint16_t ptr = static_cast<std::uint16_t>(((len & 0x3F) << 8) | payload[cursor + 1]);
            if (!jumped) {
                consumed += 2;
            }
            if (ptr >= payload.size() || jumps++ > 8) {
                return 0;
            }
            cursor = ptr;
            jumped = true;
            continue;
        }
        if (len == 0) {
            if (!jumped) {
                consumed += 1;
            }
            return consumed;
        }
        if (cursor + 1 + len > payload.size()) {
            return 0;
        }
        if (!out_name.empty()) {
            out_name.push_back('.');
        }
        out_name.append(reinterpret_cast<const char*>(&payload[cursor + 1]), len);
        if (!jumped) {
            consumed += static_cast<std::size_t>(len) + 1;
        }
        cursor += static_cast<std::size_t>(len) + 1;
    }
    return 0;
}

void parse_dns_meta(const std::vector<std::uint8_t>& payload, PacketRow& row) {
    if (payload.size() < 12) {
        return;
    }
    const std::uint16_t qdcount = static_cast<std::uint16_t>((payload[4] << 8) | payload[5]);
    const std::uint16_t ancount = static_cast<std::uint16_t>((payload[6] << 8) | payload[7]);
    std::size_t cursor = 12;
    if (qdcount > 0) {
        std::string qname;
        const std::size_t consumed = dns_read_name(payload, cursor, qname);
        if (consumed > 0 && cursor + consumed + 4 <= payload.size()) {
            row.dns_query = qname;
            row.dns_qtype = static_cast<std::int64_t>((payload[cursor + consumed] << 8) | payload[cursor + consumed + 1]);
            cursor += consumed + 4;
        } else {
            return;
        }
    }
    if (ancount == 0) {
        return;
    }
    std::string an_name;
    const std::size_t name_consumed = dns_read_name(payload, cursor, an_name);
    if (name_consumed == 0 || cursor + name_consumed + 10 > payload.size()) {
        return;
    }
    cursor += name_consumed;
    const std::uint16_t atype = static_cast<std::uint16_t>((payload[cursor] << 8) | payload[cursor + 1]);
    const std::uint16_t rdlen = static_cast<std::uint16_t>((payload[cursor + 8] << 8) | payload[cursor + 9]);
    cursor += 10;
    if (cursor + rdlen > payload.size()) {
        return;
    }
    if (atype == 1 && rdlen == 4) {
        row.dns_answer = to_ipv4(&payload[cursor]);
    } else if (atype == 28 && rdlen == 16) {
        row.dns_answer = to_ipv6(&payload[cursor]);
    }
}

void parse_http_meta(const std::vector<std::uint8_t>& payload, PacketRow& row) {
    if (payload.empty()) {
        return;
    }
    const std::size_t take = std::min<std::size_t>(payload.size(), 1024);
    std::string text(reinterpret_cast<const char*>(payload.data()), take);
    if (starts_with(text, "GET ") || starts_with(text, "POST ") || starts_with(text, "PUT ") || starts_with(text, "DELETE ") ||
        starts_with(text, "HEAD ") || starts_with(text, "OPTIONS ") || starts_with(text, "PATCH ")) {
        const std::size_t line_end = text.find("\r\n");
        const std::string first = text.substr(0, line_end == std::string::npos ? text.size() : line_end);
        const std::size_t p1 = first.find(' ');
        const std::size_t p2 = p1 == std::string::npos ? std::string::npos : first.find(' ', p1 + 1);
        if (p1 != std::string::npos && p2 != std::string::npos) {
            row.http_method = first.substr(0, p1);
            row.http_url = first.substr(p1 + 1, p2 - p1 - 1);
        }
        const std::string lower = lower_ascii_preview(payload.data(), take, 1024);
        const std::string host_key = "\r\nhost:";
        const std::size_t host_pos = lower.find(host_key);
        if (host_pos != std::string::npos) {
            const std::size_t begin = host_pos + host_key.size();
            std::size_t end = lower.find("\r\n", begin);
            if (end == std::string::npos) {
                end = lower.size();
            }
            row.http_host = lower.substr(begin, end - begin);
            while (!row.http_host.empty() && row.http_host.front() == ' ') {
                row.http_host.erase(row.http_host.begin());
            }
        }
        return;
    }
    if (starts_with(text, "HTTP/")) {
        const std::size_t p1 = text.find(' ');
        if (p1 != std::string::npos && p1 + 4 <= text.size()) {
            row.http_status = std::strtol(text.substr(p1 + 1, 3).c_str(), nullptr, 10);
        }
    }
}

void parse_tls_meta(const std::vector<std::uint8_t>& payload, PacketRow& row) {
    if (payload.size() < 11) {
        return;
    }
    if (!(payload[0] == 0x16 && payload[1] == 0x03)) {
        return;
    }
    row.tls_cipher = "tls_handshake";
    const std::size_t record_len = static_cast<std::size_t>((payload[3] << 8) | payload[4]);
    if (5 + record_len > payload.size() || payload[5] != 0x01) {
        return;
    }
    std::size_t cursor = 9;
    if (cursor + 34 > payload.size()) {
        return;
    }
    cursor += 34;
    if (cursor >= payload.size()) {
        return;
    }
    const std::size_t sid_len = payload[cursor];
    cursor += 1 + sid_len;
    if (cursor + 2 > payload.size()) {
        return;
    }
    const std::size_t cs_len = static_cast<std::size_t>((payload[cursor] << 8) | payload[cursor + 1]);
    cursor += 2;
    if (cursor + cs_len > payload.size()) {
        return;
    }
    if (cs_len >= 2) {
        std::ostringstream ss;
        ss << "0x" << std::hex << std::setw(2) << std::setfill('0') << static_cast<unsigned>(payload[cursor])
           << std::setw(2) << static_cast<unsigned>(payload[cursor + 1]);
        row.tls_cipher = ss.str();
    }
    cursor += cs_len;
    if (cursor >= payload.size()) {
        return;
    }
    const std::size_t comp_len = payload[cursor];
    cursor += 1 + comp_len;
    if (cursor + 2 > payload.size()) {
        return;
    }
    const std::size_t ext_len = static_cast<std::size_t>((payload[cursor] << 8) | payload[cursor + 1]);
    cursor += 2;
    const std::size_t ext_end = std::min(payload.size(), cursor + ext_len);
    while (cursor + 4 <= ext_end) {
        const std::uint16_t ext_type = static_cast<std::uint16_t>((payload[cursor] << 8) | payload[cursor + 1]);
        const std::uint16_t elen = static_cast<std::uint16_t>((payload[cursor + 2] << 8) | payload[cursor + 3]);
        cursor += 4;
        if (cursor + elen > ext_end) {
            break;
        }
        if (ext_type == 0 && elen >= 5) {
            std::size_t sni_cur = cursor + 2;
            const std::size_t sni_list_len = static_cast<std::size_t>((payload[cursor] << 8) | payload[cursor + 1]);
            const std::size_t sni_end = std::min(cursor + 2 + sni_list_len, cursor + elen);
            while (sni_cur + 3 <= sni_end) {
                const std::uint8_t name_type = payload[sni_cur];
                const std::size_t name_len = static_cast<std::size_t>((payload[sni_cur + 1] << 8) | payload[sni_cur + 2]);
                sni_cur += 3;
                if (sni_cur + name_len > sni_end) {
                    break;
                }
                if (name_type == 0) {
                    row.tls_sni.assign(reinterpret_cast<const char*>(&payload[sni_cur]), name_len);
                    return;
                }
                sni_cur += name_len;
            }
        }
        cursor += elen;
    }
}

struct L4Meta {
    std::size_t payload_offset{0};
    std::size_t payload_len{0};
};

bool parse_tcp_udp(const std::vector<std::uint8_t>& frame, std::size_t l4_offset, std::uint8_t proto_no, PacketRow& row, L4Meta& meta) {
    if (proto_no == 6) {
        if (l4_offset + 20 > frame.size()) {
            return false;
        }
        const std::size_t tcp_header_len = static_cast<std::size_t>((frame[l4_offset + 12] >> 4) & 0x0F) * 4;
        if (tcp_header_len < 20 || l4_offset + tcp_header_len > frame.size()) {
            return false;
        }
        row.proto = "TCP";
        row.src_port = static_cast<std::int64_t>((frame[l4_offset] << 8) | frame[l4_offset + 1]);
        row.dst_port = static_cast<std::int64_t>((frame[l4_offset + 2] << 8) | frame[l4_offset + 3]);
        row.tcp_flags_mask = static_cast<std::int64_t>(frame[l4_offset + 13]);
        meta.payload_offset = l4_offset + tcp_header_len;
        meta.payload_len = frame.size() > meta.payload_offset ? (frame.size() - meta.payload_offset) : 0;
        return true;
    }
    if (proto_no == 17) {
        if (l4_offset + 8 > frame.size()) {
            return false;
        }
        row.proto = "UDP";
        row.src_port = static_cast<std::int64_t>((frame[l4_offset] << 8) | frame[l4_offset + 1]);
        row.dst_port = static_cast<std::int64_t>((frame[l4_offset + 2] << 8) | frame[l4_offset + 3]);
        meta.payload_offset = l4_offset + 8;
        meta.payload_len = frame.size() > meta.payload_offset ? (frame.size() - meta.payload_offset) : 0;
        return true;
    }
    if (proto_no == 1 || proto_no == 58) {
        row.proto = "ICMP";
        row.src_port = 0;
        row.dst_port = 0;
        meta.payload_offset = l4_offset;
        meta.payload_len = frame.size() > meta.payload_offset ? (frame.size() - meta.payload_offset) : 0;
        return true;
    }
    return false;
}

bool resolve_ipv6_l4(const std::vector<std::uint8_t>& frame, std::size_t ip_offset, std::size_t& l4_offset, std::uint8_t& final_proto) {
    if (ip_offset + 40 > frame.size()) {
        return false;
    }
    std::uint8_t nh = frame[ip_offset + 6];
    std::size_t cursor = ip_offset + 40;
    for (int i = 0; i < 8; ++i) {
        if (nh == 0 || nh == 43 || nh == 60) {
            if (cursor + 2 > frame.size()) {
                return false;
            }
            const std::uint8_t next_nh = frame[cursor];
            const std::size_t ext_size = static_cast<std::size_t>(frame[cursor + 1] + 1) * 8;
            if (cursor + ext_size > frame.size()) {
                return false;
            }
            nh = next_nh;
            cursor += ext_size;
            continue;
        }
        if (nh == 44) {
            if (cursor + 8 > frame.size()) {
                return false;
            }
            const std::uint8_t next_nh = frame[cursor];
            nh = next_nh;
            cursor += 8;
            continue;
        }
        if (nh == 51) {
            if (cursor + 2 > frame.size()) {
                return false;
            }
            const std::uint8_t next_nh = frame[cursor];
            const std::size_t ext_size = static_cast<std::size_t>(frame[cursor + 1] + 2) * 4;
            if (cursor + ext_size > frame.size()) {
                return false;
            }
            nh = next_nh;
            cursor += ext_size;
            continue;
        }
        break;
    }
    l4_offset = cursor;
    final_proto = nh;
    return true;
}

bool parse_ipv4(const std::vector<std::uint8_t>& frame, std::size_t ip_offset, PacketRow& row, L4Meta& meta) {
    if (ip_offset + 20 > frame.size()) {
        return false;
    }
    const std::uint8_t version_ihl = frame[ip_offset];
    if ((version_ihl >> 4) != 4) {
        return false;
    }
    const std::size_t ihl = static_cast<std::size_t>(version_ihl & 0x0F) * 4;
    if (ihl < 20 || ip_offset + ihl > frame.size()) {
        return false;
    }
    const std::uint8_t proto_no = frame[ip_offset + 9];
    row.ip_version = 4;
    row.ip_ttl = static_cast<std::int64_t>(frame[ip_offset + 8]);
    const std::uint16_t frag = static_cast<std::uint16_t>((frame[ip_offset + 6] << 8) | frame[ip_offset + 7]);
    row.ip_more_frag = (frag & 0x2000) ? 1 : 0;
    row.ip_frag_offset = static_cast<std::int64_t>(frag & 0x1FFF);
    row.src_ip = to_ipv4(&frame[ip_offset + 12]);
    row.dst_ip = to_ipv4(&frame[ip_offset + 16]);
    return parse_tcp_udp(frame, ip_offset + ihl, proto_no, row, meta);
}

bool parse_ipv6(const std::vector<std::uint8_t>& frame, std::size_t ip_offset, PacketRow& row, L4Meta& meta) {
    if (ip_offset + 40 > frame.size()) {
        return false;
    }
    if ((frame[ip_offset] >> 4) != 6) {
        return false;
    }
    row.ip_version = 6;
    row.ip_ttl = static_cast<std::int64_t>(frame[ip_offset + 7]);
    row.ip_more_frag = 0;
    row.ip_frag_offset = 0;
    row.src_ip = to_ipv6(&frame[ip_offset + 8]);
    row.dst_ip = to_ipv6(&frame[ip_offset + 24]);
    std::size_t l4_offset = 0;
    std::uint8_t final_proto = 0;
    if (!resolve_ipv6_l4(frame, ip_offset, l4_offset, final_proto)) {
        return false;
    }
    return parse_tcp_udp(frame, l4_offset, final_proto, row, meta);
}

void parse_app_meta(const std::vector<std::uint8_t>& frame, const L4Meta& meta, PacketRow& row) {
    if (meta.payload_len == 0 || meta.payload_offset >= frame.size()) {
        return;
    }
    const int sport = static_cast<int>(row.src_port);
    const int dport = static_cast<int>(row.dst_port);
    const bool http_like = (sport == 80 || sport == 8080 || sport == 8000 || sport == 8888 || dport == 80 || dport == 8080 || dport == 8000 || dport == 8888);
    const bool dns_like = (sport == 53 || dport == 53) && (row.proto == "UDP" || row.proto == "TCP");
    const bool tls_like = row.proto == "TCP" && (sport == 443 || dport == 443);
    if (!http_like && !dns_like && !tls_like) {
        return;
    }
    const std::vector<std::uint8_t> payload(frame.begin() + static_cast<std::ptrdiff_t>(meta.payload_offset), frame.end());
    row.payload_preview = lower_ascii_preview(payload.data(), payload.size(), 128);
    if (http_like && row.proto == "TCP") {
        parse_http_meta(payload, row);
    }
    if (dns_like) {
        parse_dns_meta(payload, row);
    }
    if (tls_like) {
        parse_tls_meta(payload, row);
    }
}

bool parse_by_linktype(const std::vector<std::uint8_t>& frame, std::uint32_t linktype, PacketRow& row, bool enable_app_meta) {
    if (frame.empty()) {
        return false;
    }
    L4Meta meta{};
    bool ok = false;
    if (linktype == 1) {
        if (frame.size() < 14) {
            return false;
        }
        std::size_t offset = 14;
        std::uint16_t ethertype = static_cast<std::uint16_t>((frame[12] << 8) | frame[13]);
        for (int i = 0; i < 2 && (ethertype == 0x8100 || ethertype == 0x88A8); ++i) {
            if (frame.size() < offset + 4) {
                return false;
            }
            ethertype = static_cast<std::uint16_t>((frame[offset + 2] << 8) | frame[offset + 3]);
            offset += 4;
        }
        if (ethertype == 0x0800) {
            ok = parse_ipv4(frame, offset, row, meta);
        } else if (ethertype == 0x86DD) {
            ok = parse_ipv6(frame, offset, row, meta);
        }
        if (ok) {
            if (enable_app_meta) {
                parse_app_meta(frame, meta, row);
            }
            return true;
        }
        return false;
    }
    if (linktype == 101 || linktype == 228 || linktype == 229) {
        const std::uint8_t version = frame[0] >> 4;
        if (version == 4) {
            ok = parse_ipv4(frame, 0, row, meta);
        }
        if (version == 6) {
            ok = parse_ipv6(frame, 0, row, meta);
        }
        if (ok) {
            if (enable_app_meta) {
                parse_app_meta(frame, meta, row);
            }
            return true;
        }
        return false;
    }
    if (linktype == 0) {
        if (frame.size() < 4) {
            return false;
        }
        const std::uint32_t family_le = static_cast<std::uint32_t>(frame[0]) | (static_cast<std::uint32_t>(frame[1]) << 8);
        if (family_le == 2) {
            ok = parse_ipv4(frame, 4, row, meta);
        }
        if (family_le == 24 || family_le == 28 || family_le == 30) {
            ok = parse_ipv6(frame, 4, row, meta);
        }
        if (ok) {
            if (enable_app_meta) {
                parse_app_meta(frame, meta, row);
            }
            return true;
        }
        return false;
    }
    return false;
}

class NativeBatchIterator {
public:
    NativeBatchIterator(
        const std::string& file_path,
        std::uint32_t batch_size,
        std::uint32_t preview_bytes,
        bool enable_app_meta,
        std::uint32_t worker_threads)
        : file_path_(file_path),
          batch_size_(batch_size),
          preview_bytes_(preview_bytes),
          enable_app_meta_(enable_app_meta),
          worker_threads_(std::max<std::uint32_t>(1u, worker_threads)) {
        if (file_path.empty()) {
            fail("E_INVALID_ARG", "file_path is empty");
        }
        if (batch_size == 0) {
            fail("E_INVALID_ARG", "batch_size must be > 0");
        }
        file_.open(file_path, std::ios::binary);
        if (!file_.is_open()) {
            fail("E_IO_OPEN_FAILED", "cannot open file: " + file_path);
        }
        init_format();
    }

    py::dict next() {
        clear_columns();
        while (ts_col_.size() < batch_size_) {
            std::optional<PacketRow> row = read_next_row();
            if (!row.has_value()) {
                break;
            }
            push_row(*row);
        }
        if (ts_col_.empty()) {
            throw py::stop_iteration();
        }
        py::dict out;
        out["ts"] = ts_col_;
        out["src_ip"] = src_ip_col_;
        out["dst_ip"] = dst_ip_col_;
        out["src_port"] = src_port_col_;
        out["dst_port"] = dst_port_col_;
        out["proto"] = proto_col_;
        out["length"] = length_col_;
        out["direction"] = direction_col_;
        out["process_id"] = process_id_col_;
        out["process_name"] = process_name_col_;
        out["raw_hex"] = raw_hex_col_;
        out["tcp_flags_mask"] = tcp_flags_mask_col_;
        out["payload_preview"] = payload_preview_col_;
        out["http_method"] = http_method_col_;
        out["http_url"] = http_url_col_;
        out["http_host"] = http_host_col_;
        out["http_status"] = http_status_col_;
        out["dns_query"] = dns_query_col_;
        out["dns_qtype"] = dns_qtype_col_;
        out["dns_answer"] = dns_answer_col_;
        out["tls_sni"] = tls_sni_col_;
        out["tls_cipher"] = tls_cipher_col_;
        out["ip_version"] = ip_version_col_;
        out["ip_ttl"] = ip_ttl_col_;
        out["ip_frag_offset"] = ip_frag_offset_col_;
        out["ip_more_frag"] = ip_more_frag_col_;
        out["_bytes_read"] = static_cast<std::uint64_t>(current_offset());
        return out;
    }

private:
    std::string file_path_;
    std::uint32_t batch_size_{0};
    std::uint32_t preview_bytes_{0};
    bool enable_app_meta_{true};
    std::uint32_t worker_threads_{1};
    std::ifstream file_;
    FileFormat format_{FileFormat::kUnknown};

    bool little_endian_{true};
    bool pcap_ts_nano_{false};
    std::uint32_t pcap_linktype_{1};
    std::vector<std::uint32_t> pcapng_if_linktypes_;

    std::vector<double> ts_col_;
    std::vector<std::string> src_ip_col_;
    std::vector<std::string> dst_ip_col_;
    std::vector<std::int64_t> src_port_col_;
    std::vector<std::int64_t> dst_port_col_;
    std::vector<std::string> proto_col_;
    std::vector<std::int64_t> length_col_;
    std::vector<std::string> direction_col_;
    std::vector<std::int64_t> process_id_col_;
    std::vector<std::string> process_name_col_;
    std::vector<std::string> raw_hex_col_;
    std::vector<std::int64_t> tcp_flags_mask_col_;
    std::vector<std::string> payload_preview_col_;
    std::vector<std::string> http_method_col_;
    std::vector<std::string> http_url_col_;
    std::vector<std::string> http_host_col_;
    std::vector<std::int64_t> http_status_col_;
    std::vector<std::string> dns_query_col_;
    std::vector<std::int64_t> dns_qtype_col_;
    std::vector<std::string> dns_answer_col_;
    std::vector<std::string> tls_sni_col_;
    std::vector<std::string> tls_cipher_col_;
    std::vector<std::int64_t> ip_version_col_;
    std::vector<std::int64_t> ip_ttl_col_;
    std::vector<std::int64_t> ip_frag_offset_col_;
    std::vector<std::int64_t> ip_more_frag_col_;

    void clear_columns() {
        ts_col_.clear();
        src_ip_col_.clear();
        dst_ip_col_.clear();
        src_port_col_.clear();
        dst_port_col_.clear();
        proto_col_.clear();
        length_col_.clear();
        direction_col_.clear();
        process_id_col_.clear();
        process_name_col_.clear();
        raw_hex_col_.clear();
        tcp_flags_mask_col_.clear();
        payload_preview_col_.clear();
        http_method_col_.clear();
        http_url_col_.clear();
        http_host_col_.clear();
        http_status_col_.clear();
        dns_query_col_.clear();
        dns_qtype_col_.clear();
        dns_answer_col_.clear();
        tls_sni_col_.clear();
        tls_cipher_col_.clear();
        ip_version_col_.clear();
        ip_ttl_col_.clear();
        ip_frag_offset_col_.clear();
        ip_more_frag_col_.clear();
    }

    void push_row(const PacketRow& row) {
        ts_col_.push_back(row.ts);
        src_ip_col_.push_back(row.src_ip);
        dst_ip_col_.push_back(row.dst_ip);
        src_port_col_.push_back(row.src_port);
        dst_port_col_.push_back(row.dst_port);
        proto_col_.push_back(row.proto);
        length_col_.push_back(row.length);
        direction_col_.push_back(row.direction);
        process_id_col_.push_back(row.process_id);
        process_name_col_.push_back(row.process_name);
        raw_hex_col_.push_back(row.raw_hex);
        tcp_flags_mask_col_.push_back(row.tcp_flags_mask);
        payload_preview_col_.push_back(row.payload_preview);
        http_method_col_.push_back(row.http_method);
        http_url_col_.push_back(row.http_url);
        http_host_col_.push_back(row.http_host);
        http_status_col_.push_back(row.http_status);
        dns_query_col_.push_back(row.dns_query);
        dns_qtype_col_.push_back(row.dns_qtype);
        dns_answer_col_.push_back(row.dns_answer);
        tls_sni_col_.push_back(row.tls_sni);
        tls_cipher_col_.push_back(row.tls_cipher);
        ip_version_col_.push_back(row.ip_version);
        ip_ttl_col_.push_back(row.ip_ttl);
        ip_frag_offset_col_.push_back(row.ip_frag_offset);
        ip_more_frag_col_.push_back(row.ip_more_frag);
    }

    std::uint64_t current_offset() {
        const std::streampos pos = file_.tellg();
        if (pos < 0) {
            return 0;
        }
        return static_cast<std::uint64_t>(pos);
    }

    void init_format() {
        std::array<std::uint8_t, 4> first4{};
        if (!read_exact(file_, reinterpret_cast<char*>(first4.data()), first4.size())) {
            fail("E_IO_READ_FAILED", "file too small");
        }
        if (first4[0] == 0x0A && first4[1] == 0x0D && first4[2] == 0x0D && first4[3] == 0x0A) {
            format_ = FileFormat::kPcapNg;
            init_pcapng_after_magic();
            return;
        }
        format_ = FileFormat::kPcap;
        init_pcap_with_magic(first4);
    }

    void init_pcap_with_magic(const std::array<std::uint8_t, 4>& magic) {
        if (magic == std::array<std::uint8_t, 4>{0xD4, 0xC3, 0xB2, 0xA1}) {
            little_endian_ = true;
            pcap_ts_nano_ = false;
        } else if (magic == std::array<std::uint8_t, 4>{0xA1, 0xB2, 0xC3, 0xD4}) {
            little_endian_ = false;
            pcap_ts_nano_ = false;
        } else if (magic == std::array<std::uint8_t, 4>{0x4D, 0x3C, 0xB2, 0xA1}) {
            little_endian_ = true;
            pcap_ts_nano_ = true;
        } else if (magic == std::array<std::uint8_t, 4>{0xA1, 0xB2, 0x3C, 0x4D}) {
            little_endian_ = false;
            pcap_ts_nano_ = true;
        } else {
            fail("E_UNSUPPORTED_FORMAT", "unknown pcap magic");
        }
        std::array<std::uint8_t, 20> gh{};
        if (!read_exact(file_, reinterpret_cast<char*>(gh.data()), gh.size())) {
            fail("E_IO_READ_FAILED", "invalid pcap global header");
        }
        pcap_linktype_ = read_u32(&gh[16], little_endian_);
    }

    void init_pcapng_after_magic() {
        std::array<std::uint8_t, 8> hdr{};
        if (!read_exact(file_, reinterpret_cast<char*>(hdr.data()), hdr.size())) {
            fail("E_IO_READ_FAILED", "invalid pcapng section header");
        }
        const std::uint32_t total_len_le = read_u32(hdr.data(), true);
        const std::uint32_t total_len_be = read_u32(hdr.data(), false);
        std::uint32_t total_len = total_len_le;
        if (total_len < 28 || (total_len % 4) != 0) {
            total_len = total_len_be;
        }
        if (total_len < 28 || (total_len % 4) != 0) {
            fail("E_CORRUPTED_PACKET", "invalid pcapng section block length");
        }
        std::vector<std::uint8_t> body(total_len - 12);
        if (!read_exact(file_, reinterpret_cast<char*>(body.data()), body.size())) {
            fail("E_IO_READ_FAILED", "cannot read pcapng section block");
        }
        const std::array<std::uint8_t, 4> bom_le{0x4D, 0x3C, 0x2B, 0x1A};
        const std::array<std::uint8_t, 4> bom_be{0x1A, 0x2B, 0x3C, 0x4D};
        if (std::equal(body.begin(), body.begin() + 4, bom_le.begin())) {
            little_endian_ = true;
        } else if (std::equal(body.begin(), body.begin() + 4, bom_be.begin())) {
            little_endian_ = false;
        } else {
            fail("E_UNSUPPORTED_FORMAT", "pcapng byte-order magic invalid");
        }
    }

    std::optional<PacketRow> read_next_row() {
        if (format_ == FileFormat::kPcap) {
            return read_next_pcap_row();
        }
        if (format_ == FileFormat::kPcapNg) {
            return read_next_pcapng_row();
        }
        return std::nullopt;
    }

    std::optional<PacketRow> read_next_pcap_row() {
        std::array<std::uint8_t, 16> rec_hdr{};
        if (!read_exact(file_, reinterpret_cast<char*>(rec_hdr.data()), rec_hdr.size())) {
            return std::nullopt;
        }
        const std::uint32_t ts_sec = read_u32(&rec_hdr[0], little_endian_);
        const std::uint32_t ts_frac = read_u32(&rec_hdr[4], little_endian_);
        const std::uint32_t incl_len = read_u32(&rec_hdr[8], little_endian_);
        if (incl_len == 0 || incl_len > (64u * 1024u * 1024u)) {
            fail("E_CORRUPTED_PACKET", "invalid pcap incl_len");
        }
        std::vector<std::uint8_t> frame(incl_len);
        if (!read_exact(file_, reinterpret_cast<char*>(frame.data()), frame.size())) {
            fail("E_IO_READ_FAILED", "truncated pcap frame");
        }
        PacketRow row;
        row.ts = static_cast<double>(ts_sec) + static_cast<double>(ts_frac) / (pcap_ts_nano_ ? 1e9 : 1e6);
        row.length = static_cast<std::int64_t>(incl_len);
        if (preview_bytes_ > 0) {
            row.raw_hex = bytes_to_hex(frame.data(), std::min<std::size_t>(preview_bytes_, frame.size()));
        }
        if (!parse_by_linktype(frame, pcap_linktype_, row, enable_app_meta_)) {
            return std::optional<PacketRow>{};
        }
        if (row.proto != "TCP" && row.proto != "UDP" && row.proto != "ICMP") {
            return std::optional<PacketRow>{};
        }
        return row;
    }

    std::optional<PacketRow> read_next_pcapng_row() {
        while (true) {
            std::array<std::uint8_t, 8> block_hdr{};
            if (!read_exact(file_, reinterpret_cast<char*>(block_hdr.data()), block_hdr.size())) {
                return std::nullopt;
            }
            const std::uint32_t block_type = read_u32(&block_hdr[0], little_endian_);
            const std::uint32_t total_len = read_u32(&block_hdr[4], little_endian_);
            if (total_len < 12 || (total_len % 4) != 0) {
                fail("E_CORRUPTED_PACKET", "invalid pcapng block length");
            }
            std::vector<std::uint8_t> body(total_len - 12);
            if (!read_exact(file_, reinterpret_cast<char*>(body.data()), body.size())) {
                fail("E_IO_READ_FAILED", "truncated pcapng block");
            }
            std::array<std::uint8_t, 4> end_len_bytes{};
            if (!read_exact(file_, reinterpret_cast<char*>(end_len_bytes.data()), end_len_bytes.size())) {
                fail("E_IO_READ_FAILED", "truncated pcapng block tail");
            }
            const std::uint32_t end_len = read_u32(end_len_bytes.data(), little_endian_);
            if (end_len != total_len) {
                fail("E_CORRUPTED_PACKET", "pcapng block length mismatch");
            }

            if (block_type == 0x00000001) {
                if (body.size() >= 8) {
                    const std::uint16_t linktype = read_u16(body.data(), little_endian_);
                    pcapng_if_linktypes_.push_back(linktype);
                }
                continue;
            }
            if (block_type == 0x00000003) {
                if (body.size() < 4) {
                    continue;
                }
                const std::uint32_t cap_len = static_cast<std::uint32_t>(body.size() - 4);
                std::vector<std::uint8_t> frame(cap_len);
                std::copy(body.begin() + 4, body.end(), frame.begin());
                PacketRow row;
                row.ts = 0.0;
                row.length = static_cast<std::int64_t>(cap_len);
                if (preview_bytes_ > 0) {
                    row.raw_hex = bytes_to_hex(frame.data(), std::min<std::size_t>(preview_bytes_, frame.size()));
                }
                const std::uint32_t linktype = pcapng_if_linktypes_.empty() ? 1u : pcapng_if_linktypes_[0];
                if (!parse_by_linktype(frame, linktype, row, enable_app_meta_)) {
                    continue;
                }
                if (row.proto != "TCP" && row.proto != "UDP" && row.proto != "ICMP") {
                    continue;
                }
                return row;
            }
            if (block_type == 0x00000006) {
                if (body.size() < 20) {
                    continue;
                }
                const std::uint32_t interface_id = read_u32(&body[0], little_endian_);
                const std::uint32_t ts_high = read_u32(&body[4], little_endian_);
                const std::uint32_t ts_low = read_u32(&body[8], little_endian_);
                const std::uint32_t cap_len = read_u32(&body[12], little_endian_);
                if (cap_len > body.size() - 20) {
                    continue;
                }
                std::vector<std::uint8_t> frame(cap_len);
                std::copy(body.begin() + 20, body.begin() + 20 + static_cast<std::size_t>(cap_len), frame.begin());
                PacketRow row;
                const std::uint64_t ts_raw = (static_cast<std::uint64_t>(ts_high) << 32) | ts_low;
                row.ts = static_cast<double>(ts_raw) / 1e6;
                row.length = static_cast<std::int64_t>(cap_len);
                if (preview_bytes_ > 0) {
                    row.raw_hex = bytes_to_hex(frame.data(), std::min<std::size_t>(preview_bytes_, frame.size()));
                }
                std::uint32_t linktype = 1;
                if (interface_id < pcapng_if_linktypes_.size()) {
                    linktype = pcapng_if_linktypes_[interface_id];
                } else if (!pcapng_if_linktypes_.empty()) {
                    linktype = pcapng_if_linktypes_[0];
                }
                if (!parse_by_linktype(frame, linktype, row, enable_app_meta_)) {
                    continue;
                }
                if (row.proto != "TCP" && row.proto != "UDP" && row.proto != "ICMP") {
                    continue;
                }
                return row;
            }
        }
    }
};

NativeBatchIterator iter_pcap_batches(
    const std::string& file_path,
    std::uint32_t batch_size,
    std::uint32_t preview_bytes,
    bool enable_app_meta,
    std::uint32_t worker_threads) {
    return NativeBatchIterator(file_path, batch_size, preview_bytes, enable_app_meta, worker_threads);
}

py::dict build_info() {
    py::dict info;
    info["abi_version"] = 1;
    info["name"] = "traffic_core";
#if defined(_WIN64)
    info["arch"] = "win64";
#elif defined(_WIN32)
    info["arch"] = "win32";
#else
    info["arch"] = "other";
#endif
    info["supports"] = py::make_tuple("pcap", "pcapng-basic");
    return info;
}

}  // namespace

PYBIND11_MODULE(traffic_core, m) {
    m.doc() = "traffic_core native parser bridge (v1)";
    py::class_<NativeBatchIterator>(m, "_NativeBatchIterator")
        .def("__iter__", [](NativeBatchIterator& self) -> NativeBatchIterator& { return self; }, py::return_value_policy::reference_internal)
        .def("__next__", &NativeBatchIterator::next);
    m.def("build_info", &build_info, "Return build metadata");
    m.def(
        "iter_pcap_batches",
        &iter_pcap_batches,
        py::arg("file_path"),
        py::arg("batch_size"),
        py::arg("preview_bytes"),
        py::arg("enable_app_meta") = true,
        py::arg("worker_threads") = 1,
        "Iterate pcap batches in columnar dict format");
}
