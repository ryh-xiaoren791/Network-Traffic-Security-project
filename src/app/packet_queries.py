from __future__ import annotations


from src.core.filtering import match_packet_rule


def query_packets_page(
    runtime,
    *,
    page: int = 1,
    page_size: int = 500,
    process_name: str = "",
    ip: str = "",
    source: str = "",
    rule_expr: str = "",
    only_abnormal: bool = False,
    sort_key: str = "ts",
    sort_desc: bool = True,
) -> dict:
    current_page = max(1, int(page or 1))
    normalized_page_size = max(50, min(2000, int(page_size or 500)))
    normalized_sort_key = runtime._normalize_packet_sort_key(sort_key)
    extra_sql, extra_args = runtime._build_packet_rule_sql(rule_expr)
    pushdown_rule = (not str(rule_expr or "").strip()) or bool(extra_sql)
    if pushdown_rule and not only_abnormal and normalized_sort_key != "risk_level":
        offset = (current_page - 1) * normalized_page_size
        rows = runtime._query_packet_rows_chunk(
            limit=normalized_page_size,
            offset=offset,
            process_name=process_name,
            ip=ip,
            source=source,
            extra_sql=extra_sql,
            extra_args=extra_args,
            sort_key=normalized_sort_key,
            sort_desc=sort_desc,
        )
        rows = runtime._attach_packet_risk(rows) if rows else []
        if current_page == 1 and len(rows) < normalized_page_size:
            total = len(rows)
            return {
                "rows": rows,
                "total": total,
                "page": 1,
                "page_size": normalized_page_size,
                "total_pages": 1,
            }
        total = runtime._count_packet_rows(
            process_name=process_name,
            ip=ip,
            source=source,
            extra_sql=extra_sql,
            extra_args=extra_args,
        )
        total_pages = max(1, (total + normalized_page_size - 1) // normalized_page_size) if total > 0 else 1
        current_page = min(current_page, total_pages)
        if current_page != page:
            offset = (current_page - 1) * normalized_page_size
            rows = runtime._query_packet_rows_chunk(
                limit=normalized_page_size,
                offset=offset,
                process_name=process_name,
                ip=ip,
                source=source,
                extra_sql=extra_sql,
                extra_args=extra_args,
                sort_key=normalized_sort_key,
                sort_desc=sort_desc,
            )
            rows = runtime._attach_packet_risk(rows) if rows else []
        return {
            "rows": rows,
            "total": total,
            "page": current_page,
            "page_size": normalized_page_size,
            "total_pages": total_pages,
        }

    chunk_size = max(runtime._packet_query_chunk_size, normalized_page_size)
    matched_total = 0
    offset = 0
    target_start = (current_page - 1) * normalized_page_size
    target_end = target_start + normalized_page_size
    page_rows: list[dict] = []
    all_rows: list[dict] = []
    base_sort_key = normalized_sort_key if normalized_sort_key != "risk_level" else "ts"

    while True:
        chunk = runtime._query_packet_rows_chunk(
            limit=chunk_size,
            offset=offset,
            process_name=process_name,
            ip=ip,
            source=source,
            extra_sql=extra_sql,
            extra_args=extra_args,
            sort_key=base_sort_key,
            sort_desc=sort_desc,
        )
        if not chunk:
            break
        offset += len(chunk)
        chunk = runtime._attach_packet_risk(chunk)
        for row in chunk:
            if not pushdown_rule and rule_expr and not match_packet_rule(row, rule_expr, include_risk_text=True):
                continue
            if only_abnormal and str(row.get("risk_level", "normal")).lower() == "normal":
                continue
            if normalized_sort_key == "risk_level":
                all_rows.append(row)
                continue
            if target_start <= matched_total < target_end:
                page_rows.append(row)
            matched_total += 1

    if normalized_sort_key == "risk_level":
        all_rows.sort(key=lambda row: runtime._packet_sort_value(row, normalized_sort_key), reverse=sort_desc)
        matched_total = len(all_rows)
        page_rows = all_rows[target_start:target_end]

    total_pages = max(1, (matched_total + normalized_page_size - 1) // normalized_page_size) if matched_total > 0 else 1
    current_page = min(current_page, total_pages)
    if current_page != page and normalized_sort_key == "risk_level":
        target_start = (current_page - 1) * normalized_page_size
        target_end = target_start + normalized_page_size
        page_rows = all_rows[target_start:target_end]
    return {
        "rows": page_rows,
        "total": matched_total,
        "page": current_page,
        "page_size": normalized_page_size,
        "total_pages": total_pages,
    }


def query_packets_filtered(
    runtime,
    *,
    process_name: str = "",
    ip: str = "",
    source: str = "",
    rule_expr: str = "",
    only_abnormal: bool = False,
    sort_key: str = "ts",
    sort_desc: bool = True,
    max_rows: int = 20000,
) -> dict:
    normalized_sort_key = runtime._normalize_packet_sort_key(sort_key)
    limit_rows = max(100, min(200000, int(max_rows or 20000)))
    extra_sql, extra_args = runtime._build_packet_rule_sql(rule_expr)
    pushdown_rule = (not str(rule_expr or "").strip()) or bool(extra_sql)
    if pushdown_rule and not only_abnormal and normalized_sort_key != "risk_level":
        rows = runtime._query_packet_rows_chunk(
            limit=limit_rows,
            offset=0,
            process_name=process_name,
            ip=ip,
            source=source,
            extra_sql=extra_sql,
            extra_args=extra_args,
            sort_key=normalized_sort_key,
            sort_desc=sort_desc,
        )
        rows = runtime._attach_packet_risk(rows) if rows else []
        if len(rows) < limit_rows:
            return {"rows": rows, "total": len(rows), "truncated": False, "max_rows": limit_rows}
        total = runtime._count_packet_rows(
            process_name=process_name,
            ip=ip,
            source=source,
            extra_sql=extra_sql,
            extra_args=extra_args,
        )
        return {"rows": rows, "total": total, "truncated": total > len(rows), "max_rows": limit_rows}

    matched_total = 0
    offset = 0
    chunk_size = min(max(runtime._packet_query_chunk_size, 1000), 5000)
    collected_rows: list[dict] = []
    all_rows: list[dict] = []
    base_sort_key = normalized_sort_key if normalized_sort_key != "risk_level" else "ts"
    while True:
        chunk = runtime._query_packet_rows_chunk(
            limit=chunk_size,
            offset=offset,
            process_name=process_name,
            ip=ip,
            source=source,
            extra_sql=extra_sql,
            extra_args=extra_args,
            sort_key=base_sort_key,
            sort_desc=sort_desc,
        )
        if not chunk:
            break
        offset += len(chunk)
        chunk = runtime._attach_packet_risk(chunk)
        for row in chunk:
            if not pushdown_rule and rule_expr and not match_packet_rule(row, rule_expr, include_risk_text=True):
                continue
            if only_abnormal and str(row.get("risk_level", "normal")).lower() == "normal":
                continue
            matched_total += 1
            if normalized_sort_key == "risk_level":
                all_rows.append(row)
                continue
            if len(collected_rows) < limit_rows:
                collected_rows.append(row)
    if normalized_sort_key == "risk_level":
        all_rows.sort(key=lambda row: runtime._packet_sort_value(row, normalized_sort_key), reverse=sort_desc)
        matched_total = len(all_rows)
        collected_rows = all_rows[:limit_rows]
    return {"rows": collected_rows, "total": matched_total, "truncated": matched_total > len(collected_rows), "max_rows": limit_rows}


def query_offline_frames_page(
    runtime,
    *,
    page: int = 1,
    page_size: int = 500,
    search_text: str = "",
    linktype: int = 0,
) -> dict:
    if not runtime._offline_store_enabled():
        return {"rows": [], "total": 0, "page": 1, "page_size": page_size, "total_pages": 1}
    assert runtime.offline_packet_store is not None
    current_page = max(1, int(page or 1))
    normalized_page_size = max(50, min(2000, int(page_size or 500)))
    total = runtime.offline_packet_store.count_frames(source="offline", search_text=search_text, linktype=linktype)
    total_pages = max(1, (total + normalized_page_size - 1) // normalized_page_size) if total > 0 else 1
    current_page = min(current_page, total_pages)
    offset = (current_page - 1) * normalized_page_size
    rows = runtime.offline_packet_store.query_frames(
        limit=normalized_page_size,
        offset=offset,
        source="offline",
        search_text=search_text,
        linktype=linktype,
    )
    return {
        "rows": runtime._normalize_packet_rows(rows),
        "total": total,
        "page": current_page,
        "page_size": normalized_page_size,
        "total_pages": total_pages,
    }


__all__ = ["query_offline_frames_page", "query_packets_filtered", "query_packets_page"]
