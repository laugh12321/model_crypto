English | [简体中文](README_CN.md)

# Model Crypto: Python and C++ Library for Model Encryption

Model Crypto is a versatile Python and C++ library for encrypting and decrypting machine learning models. It's built on Crypto++ and offers support for various deep learning frameworks such as TensorRT, PyTorch, Paddle, and more. Use Model Crypto to safeguard your AI models with robust encryption techniques.


## Getting Started with XMake

### Requirements

- Windows: Microsoft Visual Studio (Tested with Visual Studio 2019, 2022)
- XMake (Latest version recommended)


### C++ Compilation

Compile your C++ code with the following commands, specifying the target `platform` and `architecture`:

```bash
xmake f -p {platform} -a {architecture} -m release
xmake -w
```

After compilation, you will find the C++ library in the project's root directory, including the `include` and `lib` directories. Additionally, the Python library required for building is located in `.pyd` format within the `python\model_crypto\libs` directory.

### Python Installation

To install the Python library, use the following command:

```bash
pip install .
```


## Exmaples

- [模型加密杂谈：TensorRT加密](https://www.cnblogs.com/laugh12321/p/17617526.html)

## ©️ License

Model Crypto is provided under the [MIT](./LICENSE).