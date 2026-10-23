#!/bin/bash
set -u
echo "UNAME_S $(uname -s)"
echo "UNAME_M $(uname -m)"
echo "UNAME_R $(uname -r)"
echo "UNAME_V $(uname -v)"
echo "UNAME_A $(uname -a)"
echo "CPUINFO_HEAD"
sed -n '1,12p' /proc/cpuinfo
echo "CPUINFO_VENDOR $(grep -m1 vendor_id /proc/cpuinfo || true)"
echo "CPUINFO_MODEL $(grep -m1 'model name' /proc/cpuinfo || true)"
echo "CPUINFO_FLAGS $(grep -m1 '^flags' /proc/cpuinfo || true)"
echo "CPUINFO_FEATURES $(grep -m1 '^Features' /proc/cpuinfo || true)"
if grep -m1 '^Features' /proc/cpuinfo | grep -q asimd; then
  echo "ENV_REJECTED arm_features_visible"
  exit 2
fi
if ! grep -m1 vendor_id /proc/cpuinfo | grep -Eq 'GenuineIntel|AuthenticAMD|HygonGenuine'; then
  echo "ENV_REJECTED vendor_is_not_x86"
  exit 2
fi
if [ "$(uname -s)" != "Linux" ] || [ "$(uname -m)" != "x86_64" ]; then
  echo "ENV_REJECTED not_linux_x86_64"
  exit 2
fi
echo "KERNEL_CONFIG"
cfg="/boot/config-$(uname -r)"
if [ -f "$cfg" ]; then
  grep -E 'CONFIG_IA32_EMULATION|CONFIG_X86_X32|CONFIG_X86_64=' "$cfg" || true
elif [ -f /proc/config.gz ]; then
  zcat /proc/config.gz | grep -E 'CONFIG_IA32_EMULATION|CONFIG_X86_X32|CONFIG_X86_64=' || true
else
  echo "KERNEL_CONFIG unavailable"
fi
echo "LIBSECCOMP $(dpkg -l libseccomp2 | awk '/^ii/{print $2, $3}')"
python3 parser_suite.py SCMP_ARCH_X86_64
parser_rc=$?
echo "PARSER_RC $parser_rc"
gcc -O2 -Wall -o abi abi.c -lseccomp
abi_build=$?
echo "ABI_BUILD $abi_build"
if [ "$abi_build" -eq 0 ]; then
  ./abi
  echo "ABI_RC $?"
fi
if [ "$parser_rc" -ne 0 ] || [ "$abi_build" -ne 0 ]; then
  exit 1
fi
