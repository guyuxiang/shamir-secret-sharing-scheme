# Shamir's Secret Sharing Tools

With Shamir's Secret Sharing Scheme I want to provide you an easy to use interface for this beautiful little piece of math.

## 🏠 Building the WASM for the frontend

I assume you have a [go](https://golang.org/) build environment setup in your machine. 

In order to build & pack the web assembly file for the frontend please use the following command in the top level directory:
```
./build.sh
```

This will build you the required file. You now can copy to `build` folder to your web server (or use it locally) and it
should run sss as intended.