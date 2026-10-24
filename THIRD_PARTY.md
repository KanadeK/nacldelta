# Third-party components

No third-party runtime Python dependencies, copied source, bundled binaries, fonts, or media are distributed. Python and its standard library are provided by the user's Python installation under the Python Software Foundation license. No external executable is required at runtime.

Development-only requirements are pinned in requirements-dev.txt: build (MIT), coverage (Apache-2.0), ruff (MIT), setuptools (MIT), and wheel (MIT). Their transitive dependencies are installed separately and not vendored. GitHub Actions checkout and setup-python are MIT-licensed external CI actions pinned to reviewed commit references. Project code is original and MIT-licensed; linking to research references does not relicense those sources.
