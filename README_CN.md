[English](README.md) | 简体中文 

# Model Crypto: 模型加密的Python和C++库

Model Crypto是一个多功能的Python和C++库，用于对机器学习模型进行加密和解密。它基于Crypto++构建，支持各种深度学习框架，包括TensorRT、PyTorch、Paddle等。使用Model Crypto来采用强大的加密技术保护您的AI模型。


## 通过 XMake 构建

### 要求

- Windows: Microsoft Visual Studio (已测试与Visual Studio 2019、2022)
- XMake (建议使用最新版本)


### C++编译

使用以下命令来编译您的C++代码，指定目标`platform`和`architecture`:

```bash
xmake f -p {platform} -a {architecture} -m release
xmake -w
```

编译完成后，您将在项目的根目录中找到C++库，包括`include`和`lib`目录。此外，构建Python库所需的`.pyd`文件位于`python\model_crypto\libs`目录中。

### Python安装

要安装Python库，请使用以下命令：

```bash
pip install .
```


## 示例

- [模型加密杂谈：TensorRT加密](https://www.cnblogs.com/laugh12321/p/17617526.html)


## ©️ License

Model Crypto遵循[MIT开源协议](./LICENSE)。