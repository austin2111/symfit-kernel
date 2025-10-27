project('SymCCRuntime', 'cpp', 'c')
intrinsics_gen = custom_target(
  'intrinsics_gen',
  input : [],
  output : ['intrinsics_gen.h'],
  command : [
    '/workdir/run/pyvenv/bin/meson',
    '--internal',
    'cmake_run_ctgt',
    '-o',
    '@OUTPUT@',
    '-d',
    '/workdir/run/subprojects/symcc-rt/__CMake_build/src/backends/qsym'
  ],
  depends : []
)
omp_gen = custom_target(
  'omp_gen',
  input : [],
  output : ['omp_gen.h'],
  command : [
    '/workdir/run/pyvenv/bin/meson',
    '--internal',
    'cmake_run_ctgt',
    '-o',
    '@OUTPUT@',
    '-d',
    '/workdir/run/subprojects/symcc-rt/__CMake_build/src/backends/qsym'
  ],
  depends : []
)
acc_gen = custom_target(
  'acc_gen',
  input : [],
  output : ['acc_gen.h'],
  command : [
    '/workdir/run/pyvenv/bin/meson',
    '--internal',
    'cmake_run_ctgt',
    '-o',
    '@OUTPUT@',
    '-d',
    '/workdir/run/subprojects/symcc-rt/__CMake_build/src/backends/qsym'
  ],
  depends : []
)
SymCCRtObj_dir = include_directories('src/backends/qsym', 'include', '.')
SymCCRtObj_sys = include_directories('/usr/lib/llvm-14/include', 'src/backends/qsym/qsym/qsym/pintool', is_system : true)
SymCCRtObj_inc = [SymCCRtObj_dir, SymCCRtObj_sys]
SymCCRtObj_src = files(
  'src/backends/qsym/qsym/qsym/pintool/expr.cpp',
  'src/backends/qsym/qsym/qsym/pintool/expr_builder.cpp',
  'src/backends/qsym/qsym/qsym/pintool/expr_cache.cpp',
  'src/backends/qsym/qsym/qsym/pintool/expr_evaluate.cpp',
  'src/backends/qsym/qsym/qsym/pintool/solver.cpp',
  'src/backends/qsym/qsym/qsym/pintool/dependency.cpp',
  'src/backends/qsym/qsym/qsym/pintool/logging.cpp',
  'src/backends/qsym/qsym/qsym/pintool/afl_trace_map.cpp',
  'src/backends/qsym/qsym/qsym/pintool/allocation.cpp',
  'src/backends/qsym/qsym/qsym/pintool/call_stack_manager.cpp',
  'src/backends/qsym/qsym/qsym/pintool/third_party/llvm/range.cpp',
  'src/backends/qsym/qsym/qsym/pintool/third_party/xxhash/xxhash.cpp',
  'src/Config.cpp',
  'src/RuntimeCommon.cpp',
  'src/LibcWrappers.cpp',
  'src/Shadow.cpp',
  'src/GarbageCollection.cpp',
  'src/backends/qsym/Runtime.cpp'
)
SymCCRtObj = static_library(
  'SymCCRtObj',
  SymCCRtObj_src,
  build_by_default : false,
  link_args : [],
  link_with : [],
  include_directories : SymCCRtObj_inc,
  install : false,
  override_options : [],
  objects : [],
  cpp_args : [
    '-Wredundant-decls',
    '-Wcast-align',
    '-Wmissing-include-dirs',
    '-Wswitch-default',
    '-Winvalid-pch',
    '-Wredundant-decls',
    '-Wformat=2',
    '-Wmissing-format-attribute',
    '-Wformat-nonliteral',
    '-g',
    '-D_GNU_SOURCE',
    '-D__STDC_CONSTANT_MACROS',
    '-D__STDC_FORMAT_MACROS',
    '-D__STDC_LIMIT_MACROS'
  ],
  pic : true
)
SymCCRtObj_dep = declare_dependency(
  link_with : SymCCRtObj,
  compile_args : [],
  include_directories : SymCCRtObj_inc,
  link_args : []
)
SymCCRtShared_dir = include_directories('/usr/include', '.', 'src/backends/qsym', 'include')
SymCCRtShared_sys = include_directories(is_system : true)
SymCCRtShared_inc = [SymCCRtShared_dir, SymCCRtShared_sys]
SymCCRtShared_src = files()
SymCCRtShared = shared_library(
  'SymCCRtShared',
  SymCCRtShared_src,
  build_by_default : false,
  link_args : [
    '-lz3',
    '/usr/lib/llvm-14/lib/libLLVMSupport.a',
    '-lrt',
    '-ldl',
    '-lm',
    '/usr/lib/x86_64-linux-gnu/libz.so',
    '/usr/lib/x86_64-linux-gnu/libtinfo.so',
    '/usr/lib/llvm-14/lib/libLLVMDemangle.a',
    '-lz3',
    '-lz3',
    '/usr/lib/llvm-14/lib/libLLVMSupport.a',
    '-lrt',
    '-ldl',
    '-lm',
    '/usr/lib/x86_64-linux-gnu/libz.so',
    '/usr/lib/x86_64-linux-gnu/libtinfo.so',
    '/usr/lib/llvm-14/lib/libLLVMDemangle.a'
  ],
  link_with : [],
  include_directories : SymCCRtShared_inc,
  install : false,
  override_options : [],
  objects : [
    SymCCRtObj.extract_all_objects()
  ],
  c_args : []
)
SymCCRtShared_dep = declare_dependency(
  link_with : SymCCRtShared,
  compile_args : [],
  include_directories : SymCCRtShared_inc,
  link_args : []
)
SymCCRtStatic_dir = include_directories('/usr/include', '.', 'src/backends/qsym', 'include')
SymCCRtStatic_sys = include_directories(is_system : true)
SymCCRtStatic_inc = [SymCCRtStatic_dir, SymCCRtStatic_sys]
SymCCRtStatic_src = files()
SymCCRtStatic = static_library(
  'SymCCRtStatic',
  SymCCRtStatic_src,
  build_by_default : false,
  link_args : [
    '-lz3',
    '-lz3',
    '/usr/lib/llvm-14/lib/libLLVMSupport.a',
    '-lrt',
    '-ldl',
    '-lm',
    '/usr/lib/x86_64-linux-gnu/libz.so',
    '/usr/lib/x86_64-linux-gnu/libtinfo.so',
    '/usr/lib/llvm-14/lib/libLLVMDemangle.a'
  ],
  link_with : [],
  include_directories : SymCCRtStatic_inc,
  install : false,
  override_options : [],
  objects : [
    SymCCRtObj.extract_all_objects()
  ],
  c_args : [],
  pic : false
)
SymCCRtStatic_dep = declare_dependency(
  link_with : SymCCRtStatic,
  compile_args : [],
  include_directories : SymCCRtStatic_inc,
  link_args : [
    '-lz3',
    '-lz3',
    '/usr/lib/llvm-14/lib/libLLVMSupport.a',
    '-lrt',
    '-ldl',
    '-lm',
    '/usr/lib/x86_64-linux-gnu/libz.so',
    '/usr/lib/x86_64-linux-gnu/libtinfo.so',
    '/usr/lib/llvm-14/lib/libLLVMDemangle.a'
  ]
)
