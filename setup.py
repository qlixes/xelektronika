from cx_Freeze import setup, Executable

# Dependencies are automatically detected, but it might need
# fine tuning.
buildOptions = dict(packages = [], excludes = [])

base = 'Console'

executables = [
    Executable('', base=base)
]

setup(name='restapp',
      version = '1.0',
      description = 'Rest webservices webproject with firebird',
      options = dict(build_exe = buildOptions),
      executables = executables)
