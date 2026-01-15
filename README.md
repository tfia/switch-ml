# switch-ml

Run traditional machine learning models for traffic classification on Tofino switches using P4. Reproduced and transplanted from the paper: [Do Switches Dream of Machine Learning?: Toward In-Network Classification](https://dl.acm.org/doi/10.1145/3365609.3365864). Course project for undergraduate course *Computer Network*, 2025 fall at DCST, Tsinghua University.

Currently supports:

- Decision Tree Classifier
- K-Means Clustering
- Naive Bayes Classifier
- Support Vector Machine (SVM) Classifier

For the first 2 models, the data plane codes in P4 are at `./switch`, and the control plane codes in C are at `./ctrl`.

For Naive Bayes and SVM, their codes are at `./bayes` and `./svm` respectively. Please refer to the README files in those directories for more details.

## Compile and Run

Compile the code using root:

```bash
make
./decision_tree # or ./kmeans
```

This compiles both the data plane and control plane program, and runs the control plane program for the Decision Tree Classifier. You can replace `decision_tree` with `kmeans` to run the K-Means Clustering controller program.

For Naive Bayes and SVM, please refer to their respective README files for compilation and execution instructions.

The controller program will:

- Load the P4 program to the Tofino switch data plane
- Enable the necessary ports
- Insert rules into the switch tables