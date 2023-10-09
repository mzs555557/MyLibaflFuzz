# MyLibaflFuzz
The program combines different fuzz strategies and uses them 

# Ecofuzz for example
- 1. build libpng with aflplusplus afl-clang-fast
```
./setup.sh
```
- 2. build Ecofuzz

```
cargo build --release

cp ./target/release/Ecofuzz ./
```

- 3. run fuzzer(we use forkserver Executor, if you have harness, InProcessExecutor is better, but also need rewrite fuzzer code)

```
./Ecofuzz -i ./corpus/ -o ./out -e ./libpng-1.6.37/pngcp -l ./test.log --arguments "@@" "/dev/null"
```
![微信截图_20231010023822](https://github.com/mzs555557/MyLibaflFuzz/assets/33750935/d80f601a-7b80-44a3-b90c-57cb33bd01a7)
