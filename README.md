# switch-ml

Run traditional machine learning models for traffic classification on Tofino switches using P4. Currently supports:

- Decision Tree Classifier

The data plane codes in P4 are at `./switch`, and the controller codes in C are at `./ctrl`.

## Compile and Run

Compile the code using root:

```bash
make
./control
```

The controller program will:

- Load the P4 program to the Tofino switch data plane
- Enable the necessary ports
- Insert the decision tree rules into the switch tables