from pythonforandroid.recipe import PyProjectRecipe


class KivyRecipe(PyProjectRecipe):
    version = '2.3.0'
    url = 'https://github.com/kivy/kivy/archive/refs/tags/{version}.zip'
    site_packages_name = 'kivy'
    call_hostpython_via_target = False

    depends = [('sdl2', 'sdl3'), 'setuptools', 'libthorvg']
    python_depends = ['certifi', 'chardet', 'idna', 'requests', 'urllib3', 'filetype']

    def get_recipe_env(self, arch=None):
        env = super().get_recipe_env(arch)
        if env.get('NDKPLATFORM'):
            env['KIVY_CROSS_PLATFORM'] = 'android'
        return env
