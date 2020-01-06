no relation to the sequel of some japaness super hero,

cigner writer v4 is a V4 signer library for cloud SDK.
For now only Outscale is supported, but it should be easy to support other providers

tested with tcc,clang and gcc as compiler.
tcc might leak because this library use __atribute__((cleanup()))
and glibc disable GNU attribute for compielr that are not clang or gcc
though tinycc mob branch support __atribute__((cleanup()))
so it's should be posible to have a non leaky version that use Tinycc
