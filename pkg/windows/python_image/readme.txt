# Building Windows Image
Now building Hubble on Windows is a two step process.
1. Build FIPS enabled python build. - Dockerfile_python_fips
2. Build Hubble through its Dockerfile with base as above image

## Build FIPS enabled Python build

```
cd pkg/windows/python_image
docker build -t hubble_python_fips . -m 2GB -f Dockerfile_python_fips
```

## Build Hubble

```
cd pkg/windows
docker build -t <whatever_you_want> .
```

