# switch-ml

The data plane codes in P4 are at `./switch/`, and the controller codes in C are at `./ctrl`.

## Compile and Run

Compile the code using root:

```bash
make
./control
```

This will:

- Load the P4 program to the Tofino switch data plane
- Start the controller program