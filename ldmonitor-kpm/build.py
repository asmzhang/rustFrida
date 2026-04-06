import os
import subprocess
import shutil
import zipfile
import sys
import argparse

# =======================
# 全局配置区 (Configuration Zone)
# =======================
# 指向 KernelPatch 源码文件夹的相对或绝对路径
# 如果留空 "" 或者为 None，则直接吃您系统的系统环境变量 KP_DIR 或者 Makefile 里的默认值
KP_DIR = "../SukiSU_KernelPatch_patch"

# 配置您本地特有的 NDK 绝对路径 (可选)
# 如果由于终端抽风拿不到 NDK_PATH 环境变量，且您安装的位置非系统默认位置，可在此填入。例如：
NDK_PATH = ""

# KernelSU/Magisk 模块的元信息 (在管理器中显示的内容)
PROP_ID = "kpm-dlopen-monitor"
PROP_NAME = "Frida KPM Monitor"
PROP_VERSION = "v1.0"
PROP_VERSION_CODE = "1"
PROP_AUTHOR = "Antigravity"
PROP_DESC = "自动挂载内核层的 KPM 模块"
# =======================

def run_cmd(cmd):
    print(f"[*] 执行命令: {cmd}")
    result = subprocess.run(cmd, shell=True)
    if result.returncode != 0:
        print(f"[!] 命令执行失败: {cmd}")
        sys.exit(result.returncode)

def generate_module_files(module_dir, MODULE_NAME):
    """
    通过读取 template/ 目录下的模板文件动态生成打包环境所需文件
    """
    if not os.path.exists("template"):
        print("[-] 严重错误: 找不到 template 目录，请勿删除模板。")
        sys.exit(1)
        
    prop_template_path = os.path.join("template", "module.prop")
    if os.path.exists(prop_template_path):
        with open(prop_template_path, "r", encoding="utf-8") as f:
            prop_content = f.read()
        
        prop_content = prop_content.replace("@PROP_ID@", PROP_ID)
        prop_content = prop_content.replace("@PROP_NAME@", PROP_NAME)
        prop_content = prop_content.replace("@PROP_VERSION@", PROP_VERSION)
        prop_content = prop_content.replace("@PROP_VERSION_CODE@", PROP_VERSION_CODE)
        prop_content = prop_content.replace("@PROP_AUTHOR@", PROP_AUTHOR)
        prop_content = prop_content.replace("@PROP_DESC@", PROP_DESC)
        
        with open(os.path.join(module_dir, "module.prop"), "w", encoding="utf-8") as f:
            f.write(prop_content)

    service_sh_path = os.path.join("template", "service.sh")
    if os.path.exists(service_sh_path):
        with open(service_sh_path, "r", encoding="utf-8") as f:
            service_sh = f.read()
            
        service_sh = service_sh.replace("@MODULE_NAME@", MODULE_NAME)
        
        with open(os.path.join(module_dir, "service.sh"), "w", encoding="utf-8") as f:
            f.write(service_sh)
    
    # 保证 sh 文件有执行权限 (通常打包 zip 需要注意，由于是在 Windows 生成的，直接用 zipfile 保存需要注意 external_attr，但 KernelSU 通常比较宽容或者会在安装后重置权限。保险起见通过 zipfile 写入时赋予权限)

def find_ndk_path():
    # 1. 优先检查脚本内配置的本地特殊路径
    if NDK_PATH and os.path.exists(NDK_PATH):
        # 很多用户的 NDK 路径是指向 'ndk' 目录，内部还包着 '25.2.x' 这样的版本号
        versions = [d for d in os.listdir(NDK_PATH) if os.path.isdir(os.path.join(NDK_PATH, d))]
        if versions:
            versions.sort(reverse=True)
            return os.path.join(NDK_PATH, versions[0])
        return NDK_PATH

    # 2. 从当前终端常用环境变量中读取
    # 包括 NDK_PATH, ANDROID_NDK_HOME 等
    for env_var in ["NDK_PATH", "ANDROID_NDK_HOME"]:
        ndk = os.environ.get(env_var)
        if ndk and os.path.exists(ndk):
            return ndk

    # 3. 检查 Android Home 里的 ndk 目录
    android_home = os.environ.get("ANDROID_HOME") or os.environ.get("ANDROID_SDK_ROOT")
    if android_home:
        ndk_base = os.path.join(android_home, "ndk")
        if os.path.exists(ndk_base):
            versions = [d for d in os.listdir(ndk_base) if os.path.isdir(os.path.join(ndk_base, d))]
            if versions:
                versions.sort(reverse=True)
                return os.path.join(ndk_base, versions[0])

    # 4. 从系统的 PATH 环境变量中嗅探 ndk-build 可执行文件
    ndk_build_path = shutil.which("ndk-build")
    if ndk_build_path:
        # ndk-build 就在 NDK 的根目录下！
        return os.path.dirname(ndk_build_path)

    # 5. 搜索各系统常见默认安装路径
    search_paths = []
    if os.name == "nt":
        local_appdata = os.environ.get("LOCALAPPDATA")
        if local_appdata:
            search_paths.append(os.path.join(local_appdata, "Android", "Sdk", "ndk"))
    else:
        home = os.environ.get("HOME")
        if home:
            search_paths.append(os.path.join(home, "Android", "Sdk", "ndk"))

    for base_path in search_paths:
        if os.path.exists(base_path):
            versions = [d for d in os.listdir(base_path) if os.path.isdir(os.path.join(base_path, d))]
            if versions:
                # 给所有找到的版本从大到小排序，优先取最新版本的 NDK
                versions.sort(reverse=True)
                return os.path.join(base_path, versions[0])
    
    return None

def main():
    parser = argparse.ArgumentParser(description="KPM-Build-Anywhere Ultimate Builder")
    parser.add_argument("target", nargs="?", default="all", help="要执行的目标: all (默认，构建并打包) 或 clean (仅清理)")
    parser.add_argument("--module", help="手动指定 MODULE_NAME (如果不指定，会自动查找本地第一个 .c 文件)")
    parser.add_argument("--kp-dir", help="动态指定 KernelPatch 目录的相对或绝对路径 (覆盖全局配置)")
    parser.add_argument("--ndk", help="动态指定本次使用的 NDK 绝对路径 (覆盖系统环境变量和本地推导规则)")
    
    args = parser.parse_args()

    # 0. 如果仅仅是清理行为
    if args.target == "clean":
        print("[+] 正在执行单一清理动作...")
        run_cmd("make.bat clean" if os.name == "nt" else "make clean")
        # 清理打包区
        if os.path.exists("build"):
            shutil.rmtree("build")
        sys.exit(0)

    # 1. 挂载 NDK
    ndk_path = args.ndk if args.ndk else find_ndk_path()
    if not ndk_path:
        print("[-] 🐛 致命错误: 未能通过环境变量或自动寻址找到 NDK 目录！")
        print("[-] 请核实您是否安装了 NDK，或者使用 --ndk 参数手动指定。")
        sys.exit(1)

    # 把它注入到本次执行 Python 的上下文中，使底层 Makefile / make.bat 能继承到它
    os.environ["NDK_PATH"] = ndk_path
    print(f"[*] 成功挂载 NDK 路径: {ndk_path}")

    # 2. 推导或获取 Module Name
    if args.module:
        MODULE_NAME = args.module
        print(f"[*] 通过系统传参，锁定模块名: {MODULE_NAME}")
    else:
        c_files = [f for f in os.listdir('.') if f.endswith('.c')]
        if not c_files:
            print("[-] 🐛 致命错误: 当前目录下找不到任何 .c 源文件！请手写一个或使用 --module 参数。")
            sys.exit(1)
        MODULE_NAME = os.path.splitext(c_files[0])[0]
        print(f"[*] 自动追踪到源文件: {c_files[0]} -> 锁定模块名: {MODULE_NAME}")

    print("[+] 正在清理旧构建...")
    run_cmd("make.bat clean" if os.name == "nt" else "make clean")

    print(f"[+] 正在编译模块: {MODULE_NAME}.kpm ...")
    
    # 传递 MODULE_NAME 变量给 Makefile，处理 KP_DIR
    make_args = f"MODULE_NAME={MODULE_NAME}"
    
    final_kp_dir = args.kp_dir if args.kp_dir else KP_DIR
    if final_kp_dir:
        make_args += f' KP_DIR="{final_kp_dir}"'
        
    run_cmd(f"make.bat {make_args} all" if os.name == "nt" else f"make {make_args} all")

    kpm_output = os.path.join("build", f"{MODULE_NAME}.kpm")
    if not os.path.exists(kpm_output):
        print(f"[-] 编译失败，未找到 {kpm_output}")
        sys.exit(1)

    print("[+] 正在准备打包环境...")
    # 在 build/module 下创建临时的打包工作区
    staging_dir = os.path.join("build", "module_staging")
    if os.path.exists(staging_dir):
        shutil.rmtree(staging_dir)
    os.makedirs(staging_dir)
        
    # 1. 复制编译产物 .kpm 文件
    shutil.copy(kpm_output, os.path.join(staging_dir, f"{MODULE_NAME}.kpm"))

    # 2. 动态生成 module.prop 和 service.sh
    generate_module_files(staging_dir, MODULE_NAME)

    # 3. 开始打包 Zip
    auto_zip_name = f"{PROP_ID}_{PROP_VERSION}.zip"
    zip_path = os.path.join("build", auto_zip_name)
    if os.path.exists(zip_path):
        os.remove(zip_path)

    print("[+] 正在压缩成品包...")
    with zipfile.ZipFile(zip_path, 'w', zipfile.ZIP_DEFLATED) as zf:
        for root, dirs, files in os.walk(staging_dir):
            for file in files:
                abs_path = os.path.join(root, file)
                arcname = os.path.relpath(abs_path, staging_dir)
                
                # 创建 ZipInfo，显式给予所有文件可读写权限，以及给 service.sh 执行权限
                zinfo = zipfile.ZipInfo(arcname)
                with open(abs_path, 'rb') as f:
                    file_data = f.read()
                
                if file.endswith('.sh'):
                    zinfo.external_attr = 0o755 << 16 # -rwxr-xr-x
                else:
                    zinfo.external_attr = 0o644 << 16 # -rw-r--r--
                    
                zf.writestr(zinfo, file_data)

    # 清理临时打桩目录
    shutil.rmtree(staging_dir)

    print("-" * 40)
    print("[*] 🎉 编译与打包大功告成！")
    print(f"[*] 产物生成位置: {zip_path}")
    print("-" * 40)

if __name__ == "__main__":
    main()
