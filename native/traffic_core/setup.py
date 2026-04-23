from pathlib import Path

from pybind11.setup_helpers import Pybind11Extension, build_ext
from setuptools import setup


ROOT = Path(__file__).resolve().parent

ext_modules = [
    Pybind11Extension(
        "traffic_core",
        [str(ROOT / "src" / "module.cpp")],
        cxx_std=20,
        define_macros=[("TRAFFIC_CORE_ABI_VERSION", "1")],
    )
]

setup(
    name="traffic_core",
    version="0.1.0",
    ext_modules=ext_modules,
    cmdclass={"build_ext": build_ext},
    zip_safe=False,
)
