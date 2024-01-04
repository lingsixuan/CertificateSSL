#!/bin/bash

rm -rf build
find . -name "CMakeCache.txt" -type f -delete
ANDROID_NDK_PATH="/home/ling/Android/Sdk/ndk/23.1.7779620/" # 这里替换为您的 Android NDK 路径
# ANDROID_NDK_PATH="/home/ling/Android/Sdk/ndk/ollvm/" # 这里替换为您的 Android NDK 路径
ABI_ARRAY=("armeabi-v7a" "arm64-v8a" "x86" "x86_64")
BUILD_TYPE_ARRAY=("Debug" "Release")

for abi in "${ABI_ARRAY[@]}"
do
    for build_type in "${BUILD_TYPE_ARRAY[@]}"
    do
        mkdir -p build/${abi}/${build_type}
        pushd build/${abi}/${build_type} || exit
        #cmake -Dtarget_platform=Android -DCMAKE_BUILD_TYPE=${build_type} -DANDROID_ABI=${abi} -DANDROID_NDK=${ANDROID_NDK_PATH} -DCMAKE_TOOLCHAIN_FILE=${ANDROID_NDK_PATH}/build/cmake/android.toolchain.cmake -DANDROID_PLATFORM=android-21 -DANDROID_STL=c++_shared -G "Unix Makefiles" -DCMAKE_CXX_FLAGS="-mllvm -fla -mllvm -sub -mllvm -bcf -mllvm --bcf_loop=3 -mllvm -sobf -mllvm -sub_loop=3 -mllvm -split" ../../../
        cmake -Dtarget_platform=Android -DCMAKE_BUILD_TYPE=${build_type} -DANDROID_ABI=${abi} -DANDROID_NDK=${ANDROID_NDK_PATH} -DCMAKE_TOOLCHAIN_FILE=${ANDROID_NDK_PATH}/build/cmake/android.toolchain.cmake -DANDROID_PLATFORM=android-23 -DANDROID_STL=c++_shared -G "Unix Makefiles" ../../../
        make -j
        popd || exit
    done
done

mkdir -p build/Linux/Release
pushd build/Linux/Release || exit
cmake -Dtarget_platform=Linux -DCMAKE_BUILD_TYPE=Release ../../../
make -j
popd || exit

#set(OPENSSL_ROOT_DIR /usr/local/windows/openssl)
mkdir -p build/Windows/Release
pushd build/Windows/Release || exit
cmake -Dtarget_platform=Windows -DCMAKE_BUILD_TYPE=Release -DOPENSSL_ROOT_DIR=/usr/local/windows/openssl ../../../
make -j
popd || exit

echo "构建完毕"

