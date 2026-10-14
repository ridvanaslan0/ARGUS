# Launchers

```
run/
├── windows/
│   ├── argus.cmd      double-click: opens the interactive menu
│   └── run.cmd        passes arguments through (run.cmd list)
├── linux/
│   ├── argus.sh       double-click or ./argus.sh
│   └── run.sh
└── macos/
    ├── argus.command  double-click in Finder, Terminal opens
    └── run.command
```

Each script resolves its own project root (`../../build/argus`), so the folder
can be moved anywhere on disk. Pass arguments to run a tool directly instead of
opening the menu:

```sh
./run/linux/argus.sh list
./run/linux/argus.sh aes --selftest
./run/macos/argus.command hash --alg sha3-256 "hello"
```

```bat
run\windows\run.cmd list
run\windows\run.cmd aes --selftest
```

If the binary is missing the launcher says so and points at the build command
instead of failing silently.

macOS may ask for permission the first time you double-click a `.command` file:
right-click it, choose **Open**, then confirm.