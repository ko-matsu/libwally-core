project('wally', 'c', 'cpp',
        default_options : ['warning_level=3', 'werror=false', 'buildtype=release', 'b_vscrt=mtd'],
        meson_version : '>=0.50.0')

python_exe = find_program('python3', 'python')

PACKAGE_VERSION = '0.7.4'
WALLY_PACKAGE_VERSION = PACKAGE_VERSION
SECP256K1_PACKAGE_VERSION = '0.1'

####################
# options
####################
# https://mesonbuild.com/Build-options.html

buildtype = get_option('buildtype')
debug = get_option('debug')
backend = get_option('backend')

ENABLE_SHARED = get_option('ENABLE_SHARED')
ENABLE_ELEMENTS = get_option('ENABLE_ELEMENTS')
ENABLE_TESTS = get_option('ENABLE_TESTS')
TARGET_RPATH = get_option('TARGET_RPATH')
ENABLE_COVERAGE = get_option('ENABLE_COVERAGE')
ENABLE_EXPORT_ALL = get_option('ENABLE_EXPORT_ALL')

if host_machine.system() == 'windows' or host_machine.system() == 'cygwin'
  is_windows = true
  TARGET_RPATH = ''
else
  is_windows = false
endif

if ENABLE_EXPORT_ALL and host_machine.system() != 'windows' and host_machine.system() != 'cygwin'
  ENABLE_EXPORT_ALL_OPT = '-fvisibility=hidden'
else
  ENABLE_EXPORT_ALL_OPT = ''
endif

if buildtype == 'release' and not debug
  ENABLE_DEBUG = false
  RPATH_TARGET = 'Release'
else
  ENABLE_DEBUG = true
  RPATH_TARGET = 'Debug'
  # set_property(DIRECTORY APPEND PROPERTY COMPILE_DEFINITIONS $<$<CONFIG:Debug>:DEBUGBUILD>)
endif


####################
# common setting
####################
# WALLY_BINARY_DIR_ROOT
if meson.is_subproject() == false
  WALLY_ROOT_BINARY_DIR = meson.current_build_dir()
  WALLY_OBJ_BINARY_DIR = WALLY_ROOT_BINARY_DIR + '/' + RPATH_TARGET
endif

if not ENABLE_ELEMENTS 
  ELEMENTS_COMP_OPT = ''
  ELEMENTS_SWIG_DEFINE = ''
else
  ELEMENTS_COMP_OPT = 'BUILD_ELEMENTS'
  ELEMENTS_SWIG_DEFINE = '-DBUILD_ELEMENTS'
endif

rpath_list = ''
if not is_windows
rpath_list = ['./', './build/' + RPATH_TARGET, './wallycore', '@rpath']
if TARGET_RPATH
rpath_items = TARGET_RPATH.strip().split(';')
rpath_items += ['./build/' + RPATH_TARGET, './wallycore', '@rpath']
rpath_list = './'
foreach rpath : rpath_items
  rpath_list += ':' + rpath
endforeach

endif
endif


####################
# wally common setting
####################
if ENABLE_DEBUG and ENABLE_COVERAGE
  PROFILE_ARCS_OPT = '-fprofile-arcs'
  TEST_COVERAGE_OPT = '-ftest-coverage'
  COLLECT_COVERAGE = true
  COVERAGE = true
else
  PROFILE_ARCS_OPT = ''
  TEST_COVERAGE_OPT = ''
  COLLECT_COVERAGE = false
  COVERAGE = false
endif

# if(PYTHONHOME)
# set(INCLUDE_PYTHONHOME  ${PYTHONHOME}/include)
# else()
# set(INCLUDE_PYTHONHOME  "")
# endif()

# if(MSVC)
# set(CMAKE_C_FLAGS_DEBUG "${CMAKE_C_FLAGS_DEBUG} /Od /Zi")
# set(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG} /Od /Zi")
# else()
# set(CMAKE_C_FLAGS_DEBUG "${CMAKE_C_FLAGS_DEBUG} -O0 -ggdb")
# set(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG} -O0 -ggdb")
# endif()

####################
# config.h & libsecp256k1-config.h
####################
cc = meson.get_compiler('c')
cpp = meson.get_compiler('cpp')

intsize = cc.sizeof('int')
wcharsize = cc.sizeof('wchar_t', prefix : '#include<wchar.h>')

if host_machine.system() != 'darwin'
  fallback = '\n#undef __has_include'
else
  fallback = ''
endif

conf = configuration_data()
if host_machine.system() == 'darwin'
  conf.set('AC_APPLE_UNIVERSAL_BUILD', true)
else
  conf.set('AC_APPLE_UNIVERSAL_BUILD', false)
endif

conf.set('HAVE_ASM_PAGE_H', cc.has_header('asm/page.h', prefix : fallback))
conf.set('HAVE_BYTESWAP_H_', cc.has_header('byteswap.h', prefix : fallback))
conf.set('HAVE_MEMORY_H', cc.has_header('memory.h', prefix : fallback))
conf.set('HAVE_STDINT_H', cc.has_header('stdint.h', prefix : fallback))
conf.set('HAVE_STDLIB_H', cc.has_header('stdlib.h', prefix : fallback))
conf.set('HAVE_STRINGS_H', cc.has_header('strings.h', prefix : fallback))
conf.set('HAVE_STRING_H', cc.has_header('string.h', prefix : fallback))
conf.set('HAVE_SYS_MMAN_H', cc.has_header('sys/mman.h', prefix : fallback))
conf.set('HAVE_SYS_STAT_H', cc.has_header('sys/stat.h', prefix : fallback))
conf.set('HAVE_SYS_TYPES_H', cc.has_header('sys/types.h', prefix : fallback))
conf.set('HAVE_DLFCN_H', cc.has_header('dlfcn.h', prefix : fallback))
conf.set('HAVE_INTTYPES_H', cc.has_header('inttypes.h', prefix : fallback))
conf.set('STDC_HEADERS', true)

if cc.get_id() == 'msvc'
  conf.set('HAVE_MMAP', true)
  conf.set('HAVE_UNISTD_H', true)
  conf.set('HAVE_PTHREAD', true)
  conf.set('HAVE_PTHREAD_PRIO_INHERIT', true)
  conf.set('HAVE_LIBCRYPTO', true)
else	# gcc
  # not windows
  conf.set('HAVE_MEMSET_S', cc.has_function('memset_s', prefix : fallback))
  conf.set('HAVE_EXPLICIT_BZERO', cc.has_function('explicit_bzero', prefix : fallback))
  conf.set('HAVE_EXPLICIT_MEMSET', cc.has_function('explicit_memset', prefix : fallback))
  conf.set('HAVE_MMAP', cc.has_function('mmap', prefix : fallback))

  clzll_check_code = 'int main() { __builtin_clzll(0); return 0; }'
  conf.set('HAVE_BUILTIN_CLZLL', cpp.compiles(clzll_check_code, name : 'should succeed') )

  conf.set('HAVE___INT128', true)
  conf.set('HAVE_UNISTD_H', cc.has_header('unistd.h', prefix : fallback))

  libcrypto = cc.find_library('crypto', required: false)
  conf.set('HAVE_LIBCRYPTO', libcrypto.found())

  libpthread = cc.find_library('threads', required: false)
  conf.set('HAVE_PTHREAD', libpthread.found())
  conf.set('HAVE_PTHREAD_PRIO_INHERIT', libpthread.found())
endif

conf.set('HAVE_POSIX_MEMALIGN', cc.has_header_symbol('stdlib.h', 'posix_memalign'))
conf.set('HAVE_ATTRIBUTE_WEAK', cc.compiles(
  'extern int foo(int) __attribute__((weak)); int main(void){return foo(0);}',
  name : 'should succeed') )
conf.set('HAVE_UNALIGNED_ACCESS', cc.compiles(
  'int main(void){static int a[2];return *((int*)(((char*)a)+1)) != 0;}',
  name : 'should succeed') )
conf.set('HAVE_INLINE_ASM', cc.compiles(
  'int main(void){int a = 42; int *pnt = &a; __asm__ __volatile__ (\"\" : : \"r\"(pnt) : \"memory\"); return 0;}',
  name : 'should succeed') )

if host_machine.system() != 'windows'
if host_machine.endian() == 'big'
  conf.set('WORDS_BIGENDIAN', true)
else
  conf.set('WORDS_BIGENDIAN', false)
endif
endif

if cc.has_header_symbol('sys/types.h', 'size_t') == false
if cc.sizeof('size_t') == 8
  conf.set('size_t', 'uint64_t')
else
  conf.set('size_t', 'uint32_t')
endif
endif

if cc.has_header_symbol('sys/types.h', 'ssize_t') == false
if cc.sizeof('ssize_t') == 8
  conf.set('ssize_t', 'int64_t')
else
  conf.set('ssize_t', 'int32_t')
endif
endif

#  conf.set('inline', false)

python = find_program('python3', required : false)
if not python.found()
  python = find_program('python')
endif
if python.found()
  conf.set('HAVE_PYTHON', true)
endif

# secp256k1 configure options
# ac_configure_args="${ac_configure_args} --disable-shared ${secp_jni} --with-pic --with-bignum=no --enable-experimental --enable-module-ecdh --enable-module-recovery --enable-module-rangeproof --enable-module-surjectionproof --enable-module-whitelist --enable-module-generator --enable-openssl-tests=no --enable-tests=no --enable-exhaustive-tests=no --enable-benchmark=no --disable-dependency-tracking"

# USE_ENDOMORPHISM (option only)
conf.set('ECMULT_WINDOW_SIZE', '15')
conf.set('ENABLE_MODULE_ECDH', true)
conf.set('ENABLE_MODULE_RECOVERY', true)
conf.set('ENABLE_MODULE_RANGEPROOF', true)
conf.set('ENABLE_MODULE_SURJECTIONPROOF', true)
conf.set('ENABLE_MODULE_WHITELIST', true)
conf.set('ENABLE_MODULE_GENERATOR', true)
conf.set('ENABLE_MODULE_', true)
conf.set('ENABLE_MODULE_2', true)

conf.set('HAVE_BUILTIN_POPCOUNT', cpp.compiles(
  'int main() { __builtin_popcount(0); return 0;}', name : 'should succeed') )

if not meson.is_cross_build() and host_machine.cpu_family() == 'arm'
conf.set('USE_EXTERNAL_ASM', '1')
else
conf.set('USE_ASM_X86_64', '1')
endif
conf.set('USE_ECMULT_STATIC_PRECOMPUTATION', '1')
# conf.set('USE_REDUCED_SURJECTION_PROOF_SIZE', '1')


if host_machine.system() == 'windows'
conf.set('USE_FIELD_10X26', '1')
conf.set('USE_SCALAR_8X32', '1')
else
if cc.sizeof('size_t') == 8
  conf.set('USE_FIELD_5X52', '1')
  conf.set('USE_SCALAR_4X64', '1')
else
  conf.set('USE_FIELD_10X26', '1')
  conf.set('USE_SCALAR_8X32', '1')
endif
endif
conf.set('VERSION', WALLY_PACKAGE_VERSION)

gmp = find_program('gmp', required : false)
if gmp.found()
  conf.set('USE_NUM_GMP', '1')
  conf.set('USE_FIELD_INV_NUM', '1')
  conf.set('USE_SCALAR_INV_NUM', '1')
  conf.set('HAVE_LIBGMP', '1')
else
  conf.set('USE_NUM_NONE', '1')
  conf.set('USE_FIELD_INV_BUILTIN', '1')
  conf.set('USE_SCALAR_INV_BUILTIN', '1')
endif

config_h_file = configure_file(input : 'meson/config.h.in',
  output : 'config.h',
  configuration : conf)
configure_file(input : 'meson/libsecp256k1-config.h.in',
  output : 'libsecp256k1-config.h',
  configuration : conf)
# CONFIG_HEADER_DIRECTORY = include_directories('.')
# CONFIG_HEADER_DIRECTORY = meson.current_build_dir()
CONFIG_HEADER_DIRECTORY = 'build/'
config_h_file = join_paths(CONFIG_HEADER_DIRECTORY, 'config.h')
secp256k1_config_h_file = join_paths(CONFIG_HEADER_DIRECTORY, 'libsecp256k1-config.h')


cc = meson.get_compiler('c')
load_script_file = files('meson/load_sourcefiles.py')
if backend == 'vs2019' or backend == 'vs' or backend == 'vs2017' or backend == 'vs2010' or backend == 'vs2015'
  lf_str = '\\'
  add_project_arguments('/source-charset:utf-8', '/wd4244',
      ELEMENTS_COMP_OPT, '/DWALLY_CORE_BUILD=1', '/DSECP256K1_BUILD=1', '/DHAVE_CONFIG_H',
      language : 'c')
else	# gcc
  lf_str = '/'
  add_project_arguments(
      '-Wall', '-Wextra', '-Wno-unused-function',
      PROFILE_ARCS_OPT, TEST_COVERAGE_OPT, ENABLE_EXPORT_ALL_OPT,
      ELEMENTS_COMP_OPT, '-DWALLY_CORE_BUILD=1', '-DSECP256K1_BUILD=1', '-DHAVE_CONFIG_H',
      language : 'c')
endif

####################
# secp256k1/gen_context
####################
# if(WIN32 OR XCODE)
# set(GEN_CONTEXT_PATH ${WALLY_OBJ_BINARY_DIR}/${GEN_CONTEXT_NAME})
# else()
# set(CMAKE_RUNTIME_OUTPUT_DIRECTORY  ${CMAKE_CURRENT_BINARY_DIR})
# set(GEN_CONTEXT_PATH ${CMAKE_CURRENT_BINARY_DIR}/${GEN_CONTEXT_NAME})
# endif()

SRC_WALLY_CONFIG_H = meson.current_source_dir() + '/src/config.h'
SRC_SECP256K1_CONFIG_H = meson.current_source_dir() + '/src/secp256k1/src/libsecp256k1-config.h'
SRC_ECMULT_STATIC_CONTEXT_H_PATH = join_paths(meson.current_source_dir(), 'src', 'secp256k1', 'src', 'ecmult_static_context.h')
SRC_ECMULT_STATIC_CONTEXT_H = join_paths(meson.current_build_dir(), 'src', 'secp256k1', 'ecmult_static_context.h')
SRC_SECP256K1_ECMULT_STATIC_CONTEXT_H = join_paths(meson.current_source_dir(), 'src', 'secp256k1', 'src', 'ecmult_static_context.h')
ECMULT_STATIC_CONTEXT_H_PATH = join_paths(meson.current_build_dir(), 'ecmult_static_context.h')

copy_script_file = files('meson/copy_diff_file.py')

# copy header
run_command(python_exe, copy_script_file,
    join_paths(meson.current_build_dir(), 'config.h'),
    join_paths(meson.current_build_dir(), 'src', 'secp256k1', 'config.h'))
run_command(python_exe, copy_script_file,
    join_paths(meson.current_build_dir(), 'libsecp256k1-config.h'),
    join_paths(meson.current_build_dir(), 'src', 'secp256k1', 'libsecp256k1-config.h'))

CONFIG_HEADER_DIRECTORY = join_paths(meson.current_build_dir())

subdir('src/secp256k1')
#gen_context = secp256k1.dependency('gen_context')
#secp256k1_gen_context = secp256k1.dependency('secp256k1_gen_context')

copy_script_result = run_command(python_exe, copy_script_file, SRC_ECMULT_STATIC_CONTEXT_H, ECMULT_STATIC_CONTEXT_H_PATH)
if copy_script_result.returncode() != 0
  error('Error ECMULT_STATIC_CONTEXT')
endif
ECMULT_STATIC_CONTEXT_H = copy_script_result.stdout().strip()

remove_script_file = files('meson/remove_file.py')
custom_target('remove_autotools_files',
    build_by_default: true,
    command: [python_exe, remove_script_file, SRC_ECMULT_STATIC_CONTEXT_H_PATH, SRC_SECP256K1_ECMULT_STATIC_CONTEXT_H, SRC_SECP256K1_CONFIG_H, SRC_WALLY_CONFIG_H],
    output: [])


####################
# libwally sources
####################
load_script_result = run_command(python_exe, load_script_file, 'Makefile.srclist', lf_str)
if load_script_result.returncode() != 0
  error('Makefile.srclist convert failed. ' + load_script_result.stderr().strip())
endif
LIBWALLY_SOURCES = load_script_result.stdout().strip().split('\n')
# LIBWALLY_FILES = LIBWALLY_SOURCES + files(config_h_file, secp256k1_config_h_file, ECMULT_STATIC_CONTEXT_H)

LIBWALLY_FILES = []
foreach f : LIBWALLY_SOURCES
  LIBWALLY_FILES += [files(f)]
endforeach

####################
# libwally
####################
WALLY_PROJECT_NAME = 'wally'
WALLYCORE_NAME = ' wally'

incs = include_directories('./src/secp256k1/include', './include',
    '.', './src', './src/ccan', './src/secp256k1', './src/secp256k1/src',
    CONFIG_HEADER_DIRECTORY, CONFIG_HEADER_DIRECTORY + '/src/secp256k1')

if ENABLE_SHARED
  libwally = shared_library('wally', LIBWALLY_FILES, build_rpath: rpath_list)
else
  libwally = static_library('wally', LIBWALLY_FILES)
endif

dep = declare_dependency(link_with : libwally,
                         include_directories : incs)

# FIXME
#if(COLLECT_COVERAGE)
#target_link_libraries(${PROJECT_NAME} gcov)
#endif()


####################
# libwally library
####################
WALLYCORE_NAME = ' wallycore'

if ENABLE_SHARED
  lib = shared_library('wallycore', LIBWALLY_FILES, link_with: libwally, build_rpath: rpath_list)
else
  lib = static_library('wallycore', LIBWALLY_FILES, link_with: libwally)
endif

dep2 = declare_dependency(link_with : lib,
                         include_directories : incs)
