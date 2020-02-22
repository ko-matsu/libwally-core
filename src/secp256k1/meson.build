python_exe = find_program('python3', 'python')

####################
# secp256k1/gen_context
####################
GEN_CONTEXT_NAME = 'gen_context'

# GEN_CONTEXT_PATH = join_paths(WALLY_OBJ_BINARY_DIR, GEN_CONTEXT_NAME)

# if(WIN32 OR XCODE)
# set(GEN_CONTEXT_PATH ${WALLY_OBJ_BINARY_DIR}/${GEN_CONTEXT_NAME})
# else()
# set(CMAKE_RUNTIME_OUTPUT_DIRECTORY  ${CMAKE_CURRENT_BINARY_DIR})
# set(GEN_CONTEXT_PATH ${CMAKE_CURRENT_BINARY_DIR}/${GEN_CONTEXT_NAME})
# endif()

copy_script_file = files('../../meson/copy_diff_file.py')

src_path = join_paths(meson.current_build_dir(), '..', '..', 'config.h')
dst_path = join_paths(meson.current_build_dir(), 'config.h')
copy_script_result = run_command(python_exe, copy_script_file,
    src_path, dst_path)
if copy_script_result.returncode() != 0
  error('Error config.h.')
endif
copy_script_result = run_command(python_exe, copy_script_file,
    join_paths(meson.current_build_dir(), '..', '..', 'libsecp256k1-config.h'),
    join_paths(meson.current_build_dir(), 'libsecp256k1-config.h'))
if copy_script_result.returncode() != 0
  error('Error libsecp256k1-config.h')
endif

# ECMULT_STATIC_CONTEXT_H_PATH = join_paths(meson.current_build_dir(), 'ecmult_static_context.h')
ECMULT_STATIC_CONTEXT_H_PATH = 'ecmult_static_context.h'
secp256k1_config_h_file = join_paths(CONFIG_HEADER_DIRECTORY, 'libsecp256k1-config.h')

GEN_CONTEXT_SOURCES = files('src/gen_context.c')

# cc = meson.get_compiler('c')
# if cc.get_id() == 'msvc'
#   add_project_arguments('/source-charset:utf-8', '/wd4244',
#       '/DWALLY_CORE_BUILD=1', '/DSECP256K1_BUILD=1',
#       language : 'c')
# else	# gcc
#   add_project_arguments(
#       '-Wall', '-Wextra', '-Wno-unused-function',
#       '-DWALLY_CORE_BUILD=1', '-DSECP256K1_BUILD=1',
#       language : 'c')
# endif

incs = include_directories('./include', '.', './src', './contrib',
    CONFIG_HEADER_DIRECTORY)

gen_context = executable(GEN_CONTEXT_NAME, sources : GEN_CONTEXT_SOURCES,
                 build_by_default : true, include_directories : incs)

custom_target('secp256k1_gen_context',
    build_by_default: true,
#    input: [GEN_CONTEXT_NAME],
    capture: true,
    output: [ECMULT_STATIC_CONTEXT_H_PATH],
    command: [gen_context])

# add_custom_target(ECMULT_STATIC_CONTEXT_H_PATH, 'secp256k1_gen_context')
