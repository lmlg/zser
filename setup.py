import glob
import os
import shutil
import sys
from setuptools import setup, Extension
from setuptools.command.build_ext import build_ext
from Cython.Build import cythonize

extension_modules = [
  Extension ("zser.zser", ["zser/zser.pyx"], depends = ["zser/zser.pxd"])
]

include_dirs = os.environ.get("CYTHON_INCLUDE_DIRS", ".").split (":")

base_path = os.path.dirname (__file__)

with open (os.path.join (base_path, "VERSION")) as version:
  VERSION = version.read().rstrip ()
with open (os.path.join (base_path, "zser/_version.py"), "w") as vfile:
  vfile.write ('__version__ = "%s"' % VERSION)
with open (os.path.join (base_path, "requirements.txt")) as reqs:
  requirements = reqs.read ()

class CustomBuild(build_ext):
  def run(self):
    super().run()
    suffix = '.dll' if 'win' in sys.platform.lower() else '.so'
    files = glob.glob('build/*/zser/*' + suffix)
    if files:
      shutil.copy(files[0], 'zser/zser' + suffix)

setup (
  name = "zser",
  version = VERSION,
  description = "zero-copy (de)serialization",
  author = "Luciano Lo Giudice & Agustina Arzille",
  author_email = "lmlogiudice@gmail.com",
  maintainer = "Luciano Lo Giudice",
  maintainer_email = "lmlogiudice@gmail.com",
  url = "https://github.com/lmlg/zser/",
  license = "LGPLv3",
  packages = ["zser"],
  package_dir = {"zser": "zser"},
  tests_require = ["pytest"],
  test_suite = "tests",
  install_requires = requirements,
  zip_safe = False,
  cmdclass = {'build_ext': CustomBuild},
  ext_modules = cythonize (extension_modules, include_path = include_dirs,
                           language_level = 3, annotate = True,
                           compiler_directives = {'embedsignature': True}),
)
