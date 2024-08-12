project(
  'intel-ipmi-oem',
  'cpp',
  version: '0.1',
  meson_version: '>=1.1.1',
  default_options: [
    'werror=true',
    'warning_level=3',
    'cpp_std=c++23',
  ])

# Project Arguments
all_args = [
    '-DBOOST_ERROR_CODE_HEADER_ONLY',
    '-DBOOST_SYSTEM_NO_DEPRECATED',
    '-DBOOST_ALL_NO_LIB',
    '-DBOOST_NO_RTTI',
    '-DBOOST_NO_TYPEID',
    '-DBOOST_ASIO_DISABLE_THREADS',
    '-DBOOST_COROUTINES_NO_DEPRECATION_WARNING',
    '-DBMC_VALIDATION_UNSECURE_FEATURE',
    '-DUSING_ENTITY_MANAGER_DECORATORS',
    '-Wno-psabi',
    '-Wno-pedantic',
  ]

feature_map = {
  'intel-pfr': '-DINTEL_PFR_ENABLED',
  'bmc-validation-unsecure-feature': '-DBMC_VALIDATION_UNSECURE_FEATURE',
  'using-entity-manager-decorators': '-DUSING_ENTITY_MANAGER_DECORATORS',
}

if get_option('non-intel-platforms').disabled()
  add_project_arguments('-DIF_INTEL_PLATFORMS', language: 'cpp')
endif

foreach option_key, option_value : feature_map
  if(get_option(option_key).allowed())
    summary(option_key,option_value, section : 'Enabled Features')
    add_project_arguments(option_value,language:'cpp')
  endif
endforeach

cpp = meson.get_compiler('cpp')
add_project_arguments(
  cpp.get_supported_arguments(all_args),
  language : 'cpp')

fs = import('fs')

root_inc = include_directories('.', 'include')

# Dependencies
nlohmann_json_dep = dependency('nlohmann_json', include_type: 'system')
phosphor_dbus_interfaces_dep = dependency('phosphor-dbus-interfaces')
phosphor_logging_dep = dependency('phosphor-logging')
sdbusplus_dep = dependency('sdbusplus')
ipmid_dep = dependency('libipmid')
channellayer_dep = dependency('libchannellayer')
userlayer_dep = dependency('libuserlayer')


tinyxml_dep = dependency('tinyxml2',
    default_options: ['tests=false'],
    include_type: 'system',
)

gpio_dep = dependency('libgpiodcxx',
      default_options: ['bindings=cxx'],
      )

zinteloemcmds_pre = declare_dependency(
  include_directories: root_inc,
  dependencies: [
    channellayer_dep,
    ipmid_dep,
    gpio_dep,
    nlohmann_json_dep,
    phosphor_dbus_interfaces_dep,
    phosphor_logging_dep,
    sdbusplus_dep,
    tinyxml_dep,
    userlayer_dep,
  ])

prog_python = import('python').find_installation('python3')
generate_allowlist_script = files('generate-allowlist.py')
ipmiallowlist = custom_target(
    'ipmi-allowlist.hpp',
    input: [generate_allowlist_script, 'ipmi-allowlist.conf' ],
    output: 'ipmi-allowlist.hpp',
    command: [ prog_python, '@INPUT0@', '@INPUT1@', '@OUTPUT@' ],
    )

generate_allowlist_script = files('generate-allowlist.py')
ipmisyslock = custom_target(
    'ipmi-systemlock.hpp',
    input: [generate_allowlist_script, 'ipmi-systemlock.conf'],
    output: 'ipmi-systemlock.hpp',
    command: [ prog_python, '@INPUT0@', '@INPUT1@', '@OUTPUT@' ],
    )

generate_allowlist_script = files('generate-allowlist.py')
ipmiblocklist = custom_target(
    'ipmi-blocklist.hpp',
    input: [generate_allowlist_script, 'ipmi-blocklist.conf'],
    output: 'ipmi-blocklist.hpp',
    command: [ prog_python, '@INPUT0@', '@INPUT1@', '@OUTPUT@' ],
    )

zinteloemcmds_src = [
  'src/oemcommands.cpp',
  'src/sensorcommands.cpp',
  'src/biosconfigcommands.cpp',
  'src/storagecommands.cpp',
  'src/multinodecommands.cpp',
  'src/firmware-update.cpp',
  'src/appcommands.cpp',
  'src/smbiosmdrv2handler.cpp',
  'src/manufacturingcommands.cpp',
  'src/bmccontrolservices.cpp',
  'src/bridgingcommands.cpp',
  'src/ipmi_to_redfish_hooks.cpp',
  'src/me_to_redfish_hooks.cpp',
  'src/chassiscommands.cpp',
  'src/allowlist-filter.cpp',
  'src/fruutils.cpp',
  ipmiallowlist,
  ipmisyslock,
  ipmiblocklist,
]

zinteloemcmds_lib = library(
  'zinteloemcmds',
  sources: zinteloemcmds_src,
  implicit_include_directories: false,
  dependencies: zinteloemcmds_pre,
  version: meson.project_version(),
  override_options: ['b_lundef=false'],
  install: true,
  install_dir: get_option('libdir') / 'ipmid-providers')

if get_option('tests').allowed()
  subdir('tests')
endif


conf_data = configuration_data()
conf_data.set10('IPMI_FIREWALL',get_option('ipmi-firewall'))
conf_data.set10('DISABLE_SPECIAL_MODE',get_option('disable-special-mode'))
conf_data.set10('CONFIGURABLE_FRU' ,get_option('configurable-fru'))

configure_file(output: 'config.h',
  configuration: conf_data
)
