import os
import sys
import shutil
import subprocess

version = sys.argv[1]
sys_name = sys.argv[2]
arch = sys.argv[3]

archive_name = f"iodine-{version}-{sys_name}-{arch}"
staging_dir = os.path.abspath("zip_staging")
if os.path.exists(staging_dir):
    shutil.rmtree(staging_dir)
env = os.environ.copy()
env["DESTDIR"] = os.path.join(staging_dir, archive_name)
subprocess.run(["meson", "install", "--no-rebuild"], env=env, check=True)
fmt = "zip" if sys_name in ["windows","android"] else "gztar"
zip_path = shutil.make_archive(archive_name, fmt, root_dir=staging_dir)
shutil.rmtree(staging_dir)
print(f"\nCreated package: {zip_path}")
