# 1. 概述
## 1.1 制品信息
容器镜像 sonobuoy/kube-hunter:v0.2.0 基于 alpine 3.10.3 操作系统构建，适用于 amd64 架构，并在 2024-11-12 15:53:21 的安全扫描中发现了潜在的安全问题。

| 制品类型 | 容器镜像 |
|--- | --- |
| 制品名称 | sonobuoy/kube-hunter:v0.2.0 |
| 创建时间 | 2020-01-24 04:44:17 |
| 架构 | amd64 |
| 操作系统 | alpine 3.10.3 |
| 镜像 ID | sha256:983660753fb37dd81c08ce15a25c00bc0981813721ce14a1a2c9a1e953f533a9 |
| 仓库标签 | sonobuoy/kube-hunter:v0.2.0 |
| Docker 版本 | 19.03.5 |
| 扫描时间 | 2024-11-12 15:53:21 |

## 1.2 镜像配置
镜像创建历史记录如下所示，请手动检查是否有可疑的执行命令，例如下载恶意文件等。

| 创建时间 | 历史记录 |
|--- | --- |
| 2019-10-21 17:21:42 | /bin/sh -c #(nop) ADD file:fe1f09249227e2da2089afb4d07e16cbf832eeb804120074acd2b8192876cd28 in /  |
| 2019-10-21 17:21:42 | /bin/sh -c #(nop)  CMD ["/bin/sh"] |
| 2019-10-21 18:28:51 | /bin/sh -c #(nop)  ENV PATH=/usr/local/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin |
| 2019-10-21 19:53:36 | /bin/sh -c #(nop)  ENV LANG=C.UTF-8 |
| 2019-10-21 19:53:37 | /bin/sh -c apk add --no-cache ca-certificates |
| 2019-10-21 20:05:00 | /bin/sh -c #(nop)  ENV GPG_KEY=0D96DF4D4110E5C43FBFB17F2D347EA6AA65421D |
| 2019-10-21 20:05:00 | /bin/sh -c #(nop)  ENV PYTHON_VERSION=3.7.5 |
| 2019-11-15 03:09:43 | /bin/sh -c set -ex 	&& apk add --no-cache --virtual .fetch-deps 		gnupg 		tar 		xz 		&& wget -O python.tar.xz "https://www.python.org/ftp/python/${PYTHON_VERSION%%[a-z]*}/Python-$PYTHON_VERSION.tar.xz" 	&& wget -O python.tar.xz.asc "https://www.python.org/ftp/python/${PYTHON_VERSION%%[a-z]*}/Python-$PYTHON_VERSION.tar.xz.asc" 	&& export GNUPGHOME="$(mktemp -d)" 	&& gpg --batch --keyserver ha.pool.sks-keyservers.net --recv-keys "$GPG_KEY" 	&& gpg --batch --verify python.tar.xz.asc python.tar.xz 	&& { command -v gpgconf > /dev/null && gpgconf --kill all || :; } 	&& rm -rf "$GNUPGHOME" python.tar.xz.asc 	&& mkdir -p /usr/src/python 	&& tar -xJC /usr/src/python --strip-components=1 -f python.tar.xz 	&& rm python.tar.xz 		&& apk add --no-cache --virtual .build-deps  		bzip2-dev 		coreutils 		dpkg-dev dpkg 		expat-dev 		findutils 		gcc 		gdbm-dev 		libc-dev 		libffi-dev 		libnsl-dev 		libtirpc-dev 		linux-headers 		make 		ncurses-dev 		openssl-dev 		pax-utils 		readline-dev 		sqlite-dev 		tcl-dev 		tk 		tk-dev 		util-linux-dev 		xz-dev 		zlib-dev 	&& apk del .fetch-deps 		&& cd /usr/src/python 	&& gnuArch="$(dpkg-architecture --query DEB_BUILD_GNU_TYPE)" 	&& ./configure 		--build="$gnuArch" 		--enable-loadable-sqlite-extensions 		--enable-optimizations 		--enable-shared 		--with-system-expat 		--with-system-ffi 		--without-ensurepip 	&& make -j "$(nproc)" 		EXTRA_CFLAGS="-DTHREAD_STACK_SIZE=0x100000" 		PROFILE_TASK='-m test.regrtest --pgo 			test_array 			test_base64 			test_binascii 			test_binhex 			test_binop 			test_bytes 			test_c_locale_coercion 			test_class 			test_cmath 			test_codecs 			test_compile 			test_complex 			test_csv 			test_decimal 			test_dict 			test_float 			test_fstring 			test_hashlib 			test_io 			test_iter 			test_json 			test_long 			test_math 			test_memoryview 			test_pickle 			test_re 			test_set 			test_slice 			test_struct 			test_threading 			test_time 			test_traceback 			test_unicode 		' 	&& make install 		&& find /usr/local -type f -executable -not \( -name '*tkinter*' \) -exec scanelf --needed --nobanner --format '%n#p' '{}' ';' 		| tr ',' '\n' 		| sort -u 		| awk 'system("[ -e /usr/local/lib/" $1 " ]") == 0 { next } { print "so:" $1 }' 		| xargs -rt apk add --no-cache --virtual .python-rundeps 	&& apk del .build-deps 		&& find /usr/local -depth 		\( 			\( -type d -a \( -name test -o -name tests -o -name idle_test \) \) 			-o 			\( -type f -a \( -name '*.pyc' -o -name '*.pyo' \) \) 		\) -exec rm -rf '{}' + 	&& rm -rf /usr/src/python 		&& python3 --version |
| 2019-11-15 03:09:44 | /bin/sh -c cd /usr/local/bin 	&& ln -s idle3 idle 	&& ln -s pydoc3 pydoc 	&& ln -s python3 python 	&& ln -s python3-config python-config |
| 2019-11-15 03:09:44 | /bin/sh -c #(nop)  ENV PYTHON_PIP_VERSION=19.3.1 |
| 2019-11-15 03:09:44 | /bin/sh -c #(nop)  ENV PYTHON_GET_PIP_URL=https://github.com/pypa/get-pip/raw/ffe826207a010164265d9cc807978e3604d18ca0/get-pip.py |
| 2019-11-15 03:09:44 | /bin/sh -c #(nop)  ENV PYTHON_GET_PIP_SHA256=b86f36cc4345ae87bfd4f10ef6b2dbfa7a872fbff70608a1e43944d283fd0eee |
| 2019-11-15 03:09:49 | /bin/sh -c set -ex; 		wget -O get-pip.py "$PYTHON_GET_PIP_URL"; 	echo "$PYTHON_GET_PIP_SHA256 *get-pip.py" | sha256sum -c -; 		python get-pip.py 		--disable-pip-version-check 		--no-cache-dir 		"pip==$PYTHON_PIP_VERSION" 	; 	pip --version; 		find /usr/local -depth 		\( 			\( -type d -a \( -name test -o -name tests -o -name idle_test \) \) 			-o 			\( -type f -a \( -name '*.pyc' -o -name '*.pyo' \) \) 		\) -exec rm -rf '{}' +; 	rm -f get-pip.py |
| 2019-11-15 03:09:49 | /bin/sh -c #(nop)  CMD ["python3"] |
| 2019-11-21 02:27:52 | /bin/sh -c apk add --no-cache     tcpdump |
| 2019-11-21 02:27:54 | /bin/sh -c apk upgrade --no-cache |
| 2020-01-23 20:44:16 | /bin/sh -c #(nop) COPY dir:4aa88aa29832de442fb0e6eced064257cc64c2c748c8eeefc2bd85fea78dd4e8 in /kube-hunter  |
| 2020-01-23 20:44:16 | /bin/sh -c #(nop) WORKDIR /kube-hunter |
| 2020-01-23 20:44:17 | /bin/sh -c #(nop)  ENTRYPOINT ["python" "kube-hunter.py"] |

镜像配置信息如下所示，请手动检查是否有可疑的执行命令和暴露的 secret，例如执行恶意命令和应用程序密钥等。

| 配置类型 | 内容 |
|--- | --- |
| 环境变量 | PATH=/usr/local/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin |
| 环境变量 | LANG=C.UTF-8 |
| 环境变量 | GPG_KEY=0D96DF4D4110E5C43FBFB17F2D347EA6AA65421D |
| 环境变量 | PYTHON_VERSION=3.7.5 |
| 环境变量 | PYTHON_PIP_VERSION=19.3.1 |
| 环境变量 | PYTHON_GET_PIP_URL=https://github.com/pypa/get-pip/raw/ffe826207a010164265d9cc807978e3604d18ca0/get-pip.py |
| 环境变量 | PYTHON_GET_PIP_SHA256=b86f36cc4345ae87bfd4f10ef6b2dbfa7a872fbff70608a1e43944d283fd0eee |

## 1.3 漏洞概览
本次共扫描出 43 个漏洞，超危漏洞有 1 个，占比 2.33% ；高危漏洞有 19 个，占比 44.19% 。

|  | 超危 | 高危 | 中危 | 低危 | 未知 | 总计 |
|--- | --- | --- | --- | --- | --- | --- |
| 系统层组件漏洞：sonobuoy/kube-hunter:v0.2.0 (alpine 3.10.3) | 1 | 13 | 12 | 2 | 0 | 28 |
| 应用层组件漏洞：Python | 0 | 6 | 9 | 0 | 0 | 15 |
| 漏洞总数 | 1 | 19 | 21 | 2 | 0 | 43 |

其中可修复的漏洞有 43 个，占比 100.00% 。

| 可修复漏洞 | 漏洞数量 |
|--- | --- |
| CVE-2021-28831 : busybox: invalid free or segmentation fault via malformed gzip data | 2 |
| CVE-2021-3449 : openssl: NULL pointer dereference in signature_algorithms processing | 2 |
| CVE-2019-1551 : openssl: Integer overflow in RSAZ modular exponentiation on x86_64 | 2 |
| CVE-2021-3450 : openssl: CA certificate check bypass with X509_V_FLAG_X509_STRICT | 2 |
| CVE-2020-28928 : In musl libc through 1.2.1, wcsnrtombs mishandles particular combinati ... | 2 |
| CVE-2021-23841 : openssl: NULL pointer dereference in X509_issuer_and_serial_hash() | 2 |
| CVE-2021-23839 : openssl: incorrect SSLv2 rollback protection | 2 |
| CVE-2020-1967 : openssl: Segmentation fault in SSL_check_chain causes denial of service | 2 |
| CVE-2021-23840 : openssl: integer overflow in CipherUpdate | 2 |
| CVE-2020-1971 : openssl: EDIPARTYNAME NULL pointer de-reference | 2 |
| CVE-2020-28196 : krb5: unbounded recursion via an ASN.1-encoded Kerberos message in lib/krb5/asn.1/asn1_encode.c may lead to DoS | 1 |
| CVE-2023-37920 : python-certifi: Removal of e-Tugra root certificate | 1 |
| CVE-2023-32681 : python-requests: Unintended leak of Proxy-Authorization header | 1 |
| CVE-2024-6345 : pypa/setuptools: Remote code execution via download functions in the package_index module in pypa/setuptools | 1 |
| CVE-2020-8037 : tcpdump: ppp decapsulator can be convinced to allocate a large amount of memory | 1 |
| CVE-2021-3572 : python-pip: Incorrect handling of unicode separators in git references | 1 |
| CVE-2021-30139 | 1 |
| CVE-2022-40899 : python-future: remote attackers can cause denial of service via crafted Set-Cookie header from malicious web server | 1 |
| CVE-2023-43804 : python-urllib3: Cookie request header isn't stripped during cross-origin redirects | 1 |
| CVE-2022-40898 : python-wheel: remote attackers can cause denial of service via attacker controlled input to wheel cli | 1 |
| CVE-2019-19242 : sqlite: SQL injection in sqlite3ExprCodeTarget in expr.c | 1 |
| CVE-2024-3651 : python-idna: potential DoS via resource consumption via specially crafted inputs to idna.encode() | 1 |
| CVE-2020-26137 : python-urllib3: CRLF injection via HTTP request method | 1 |
| CVE-2023-5752 : pip: Mercurial configuration injectable in repo revision when installing via pip | 1 |
| CVE-2024-35195 : requests: subsequent requests to the same host ignore cert verification | 1 |
| CVE-2022-40897 : pypa-setuptools: Regular Expression Denial of Service (ReDoS) in package_index.py | 1 |
| CVE-2020-11655 : sqlite: malformed window-function query leads to DoS | 1 |
| CVE-2022-23491 : python-certifi: untrusted root certificates | 1 |
| CVE-2023-45803 : urllib3: Request body not stripped after redirect from 303 status changes request method to GET | 1 |
| CVE-2019-19244 : sqlite: allows a crash if a sub-select uses both DISTINCT and window functions and also has certain ORDER BY usage | 1 |
| CVE-2024-37891 : urllib3: proxy-authorization request header is not stripped during cross-origin redirects | 1 |
| CVE-2021-36159 : libfetch: an out of boundary read while libfetch uses strtol to parse the relevant numbers into address bytes leads to information leak or crash | 1 |
| CVE-2019-5188 : e2fsprogs: Out-of-bounds write in e2fsck/rehash.c | 1 |

包含漏洞的软件包如下所示。

| 软件包名称 | 包含的漏洞数量 |
|--- | --- |
| libssl1.1 | 8 |
| libcrypto1.1 | 8 |
| urllib3 | 4 |
| sqlite-libs | 3 |
| apk-tools | 2 |
| requests | 2 |
| certifi | 2 |
| setuptools | 2 |
| pip | 2 |
| libcom_err | 1 |
| musl-utils | 1 |
| ssl_client | 1 |
| idna | 1 |
| musl | 1 |
| future | 1 |
| tcpdump | 1 |
| krb5-libs | 1 |
| busybox | 1 |
| wheel | 1 |

全量漏洞如下所示，漏洞详情请看第 2 部分的扫描结果。

| 漏洞名称 | 漏洞数量 |
|--- | --- |
| CVE-2021-23840 : openssl: integer overflow in CipherUpdate | 2 |
| CVE-2021-23841 : openssl: NULL pointer dereference in X509_issuer_and_serial_hash() | 2 |
| CVE-2021-3450 : openssl: CA certificate check bypass with X509_V_FLAG_X509_STRICT | 2 |
| CVE-2020-1967 : openssl: Segmentation fault in SSL_check_chain causes denial of service | 2 |
| CVE-2021-28831 : busybox: invalid free or segmentation fault via malformed gzip data | 2 |
| CVE-2020-28928 : In musl libc through 1.2.1, wcsnrtombs mishandles particular combinati ... | 2 |
| CVE-2021-3449 : openssl: NULL pointer dereference in signature_algorithms processing | 2 |
| CVE-2021-23839 : openssl: incorrect SSLv2 rollback protection | 2 |
| CVE-2019-1551 : openssl: Integer overflow in RSAZ modular exponentiation on x86_64 | 2 |
| CVE-2020-1971 : openssl: EDIPARTYNAME NULL pointer de-reference | 2 |
| CVE-2020-26137 : python-urllib3: CRLF injection via HTTP request method | 1 |
| CVE-2021-30139 | 1 |
| CVE-2022-40898 : python-wheel: remote attackers can cause denial of service via attacker controlled input to wheel cli | 1 |
| CVE-2024-6345 : pypa/setuptools: Remote code execution via download functions in the package_index module in pypa/setuptools | 1 |
| CVE-2022-23491 : python-certifi: untrusted root certificates | 1 |
| CVE-2023-45803 : urllib3: Request body not stripped after redirect from 303 status changes request method to GET | 1 |
| CVE-2023-43804 : python-urllib3: Cookie request header isn't stripped during cross-origin redirects | 1 |
| CVE-2021-36159 : libfetch: an out of boundary read while libfetch uses strtol to parse the relevant numbers into address bytes leads to information leak or crash | 1 |
| CVE-2019-19242 : sqlite: SQL injection in sqlite3ExprCodeTarget in expr.c | 1 |
| CVE-2023-32681 : python-requests: Unintended leak of Proxy-Authorization header | 1 |
| CVE-2019-19244 : sqlite: allows a crash if a sub-select uses both DISTINCT and window functions and also has certain ORDER BY usage | 1 |
| CVE-2024-37891 : urllib3: proxy-authorization request header is not stripped during cross-origin redirects | 1 |
| CVE-2019-5188 : e2fsprogs: Out-of-bounds write in e2fsck/rehash.c | 1 |
| CVE-2021-3572 : python-pip: Incorrect handling of unicode separators in git references | 1 |
| CVE-2020-11655 : sqlite: malformed window-function query leads to DoS | 1 |
| CVE-2024-3651 : python-idna: potential DoS via resource consumption via specially crafted inputs to idna.encode() | 1 |
| CVE-2023-37920 : python-certifi: Removal of e-Tugra root certificate | 1 |
| CVE-2022-40899 : python-future: remote attackers can cause denial of service via crafted Set-Cookie header from malicious web server | 1 |
| CVE-2022-40897 : pypa-setuptools: Regular Expression Denial of Service (ReDoS) in package_index.py | 1 |
| CVE-2020-28196 : krb5: unbounded recursion via an ASN.1-encoded Kerberos message in lib/krb5/asn.1/asn1_encode.c may lead to DoS | 1 |
| CVE-2020-8037 : tcpdump: ppp decapsulator can be convinced to allocate a large amount of memory | 1 |
| CVE-2023-5752 : pip: Mercurial configuration injectable in repo revision when installing via pip | 1 |
| CVE-2024-35195 : requests: subsequent requests to the same host ignore cert verification | 1 |

# 2. 扫描结果
## 2.1 sonobuoy/kube-hunter:v0.2.0 (alpine 3.10.3)
| 扫描目标 | sonobuoy/kube-hunter:v0.2.0 (alpine 3.10.3) |
|--- | --- |
| 软件包类型 | 系统层软件包 |
| 目标类型 | alpine |

### 2.1.1 CVE-2021-36159:libfetch: an out of boundary read while libfetch uses strtol to parse the relevant numbers into address bytes leads to information leak or crash
#### 2.1.1.1 软件包信息
| 软件包 URL | pkg:apk/alpine/apk-tools@2.10.4-r2?arch=x86_64&distro=3.10.3 |
|--- | --- |
| 软件包名称 | apk-tools |
| 安装版本 | 2.10.4-r2 |
| 软件包 ID | apk-tools@2.10.4-r2 |
| 修复版本 | 2.10.7-r0 |

#### 2.1.1.2 漏洞信息
| 漏洞编号 | CVE-2021-36159 |
|--- | --- |
| 威胁等级 | CRITICAL |
| 状态 | fixed |
| 漏洞标题 | libfetch: an out of boundary read while libfetch uses strtol to parse the relevant numbers into address bytes leads to information leak or crash |
| 威胁等级来源 | nvd |
| 披露时间 | 2021-08-03 14:15:08 |
| 上次修改时间 | 2023-11-07 03:36:43 |

#### 2.1.1.3 漏洞描述
libfetch before 2021-07-26, as used in apk-tools, xbps, and other products, mishandles numeric strings for the FTP and HTTP protocols. The FTP passive mode implementation allows an out-of-bounds read because strtol is used to parse the relevant numbers into address bytes. It does not check if the line ends prematurely. If it does, the for-loop condition checks for the '\0' terminator one byte too late.

#### 2.1.1.4 相关链接
- https://avd.aquasec.com/nvd/cve-2021-36159
- https://secdb.alpinelinux.org/
- https://access.redhat.com/security/cve/CVE-2021-36159
- https://github.com/freebsd/freebsd-src/commits/main/lib/libfetch
- https://gitlab.alpinelinux.org/alpine/apk-tools/-/issues/10749
- https://lists.apache.org/thread.html/r61db8e7dcb56dc000a5387a88f7a473bacec5ee01b9ff3f55308aacc%40%3Cdev.kafka.apache.org%3E
- https://lists.apache.org/thread.html/r61db8e7dcb56dc000a5387a88f7a473bacec5ee01b9ff3f55308aacc%40%3Cusers.kafka.apache.org%3E
- https://lists.apache.org/thread.html/rbf4ce74b0d1fa9810dec50ba3ace0caeea677af7c27a97111c06ccb7%40%3Cdev.kafka.apache.org%3E
- https://lists.apache.org/thread.html/rbf4ce74b0d1fa9810dec50ba3ace0caeea677af7c27a97111c06ccb7%40%3Cusers.kafka.apache.org%3E
- https://nvd.nist.gov/vuln/detail/CVE-2021-36159
- https://www.cve.org/CVERecord?id=CVE-2021-36159

### 2.1.2 CVE-2021-30139
#### 2.1.2.1 软件包信息
| 软件包 URL | pkg:apk/alpine/apk-tools@2.10.4-r2?arch=x86_64&distro=3.10.3 |
|--- | --- |
| 软件包名称 | apk-tools |
| 安装版本 | 2.10.4-r2 |
| 软件包 ID | apk-tools@2.10.4-r2 |
| 修复版本 | 2.10.6-r0 |

#### 2.1.2.2 漏洞信息
| 漏洞编号 | CVE-2021-30139 |
|--- | --- |
| 威胁等级 | HIGH |
| 状态 | fixed |
| 威胁等级来源 | nvd |
| 披露时间 | 2021-04-21 16:15:08 |
| 上次修改时间 | 2021-04-22 18:21:47 |

#### 2.1.2.3 漏洞描述
In Alpine Linux apk-tools before 2.12.5, the tarball parser allows a buffer overflow and crash.

#### 2.1.2.4 相关链接
- https://avd.aquasec.com/nvd/cve-2021-30139
- https://secdb.alpinelinux.org/
- https://gitlab.alpinelinux.org/alpine/apk-tools/-/issues/10741
- https://gitlab.alpinelinux.org/alpine/aports/-/issues/12606

### 2.1.3 CVE-2021-28831:busybox: invalid free or segmentation fault via malformed gzip data
#### 2.1.3.1 软件包信息
| 软件包 URL | pkg:apk/alpine/busybox@1.30.1-r3?arch=x86_64&distro=3.10.3 |
|--- | --- |
| 软件包名称 | busybox |
| 安装版本 | 1.30.1-r3 |
| 软件包 ID | busybox@1.30.1-r3 |
| 修复版本 | 1.30.1-r5 |

#### 2.1.3.2 漏洞信息
| 漏洞编号 | CVE-2021-28831 |
|--- | --- |
| 威胁等级 | HIGH |
| 状态 | fixed |
| 漏洞标题 | busybox: invalid free or segmentation fault via malformed gzip data |
| 威胁等级来源 | nvd |
| 披露时间 | 2021-03-19 05:15:13 |
| 上次修改时间 | 2023-11-07 03:32:23 |

#### 2.1.3.3 漏洞描述
decompress_gunzip.c in BusyBox through 1.32.1 mishandles the error bit on the huft_build result pointer, with a resultant invalid free or segmentation fault, via malformed gzip data.

#### 2.1.3.4 相关链接
- https://avd.aquasec.com/nvd/cve-2021-28831
- https://secdb.alpinelinux.org/
- https://access.redhat.com/security/cve/CVE-2021-28831
- https://git.busybox.net/busybox/commit/?id=f25d254dfd4243698c31a4f3153d4ac72aa9e9bd
- https://lists.debian.org/debian-lts-announce/2021/04/msg00001.html
- https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/3UDQGJRECXFS5EZVDH2OI45FMO436AC4/
- https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/Z7ZIFKPRR32ZYA3WAA2NXFA3QHHOU6FJ/
- https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/ZASBW7QRRLY5V2R44MQ4QQM4CZIDHM2U/
- https://nvd.nist.gov/vuln/detail/CVE-2021-28831
- https://security.gentoo.org/glsa/202105-09
- https://ubuntu.com/security/notices/USN-5179-1
- https://ubuntu.com/security/notices/USN-5179-2
- https://ubuntu.com/security/notices/USN-6335-1
- https://www.cve.org/CVERecord?id=CVE-2021-28831

### 2.1.4 CVE-2020-28196:krb5: unbounded recursion via an ASN.1-encoded Kerberos message in lib/krb5/asn.1/asn1_encode.c may lead to DoS
#### 2.1.4.1 软件包信息
| 软件包 URL | pkg:apk/alpine/krb5-libs@1.17-r0?arch=x86_64&distro=3.10.3 |
|--- | --- |
| 软件包名称 | krb5-libs |
| 安装版本 | 1.17-r0 |
| 软件包 ID | krb5-libs@1.17-r0 |
| 修复版本 | 1.17.2-r0 |

#### 2.1.4.2 漏洞信息
| 漏洞编号 | CVE-2020-28196 |
|--- | --- |
| 威胁等级 | HIGH |
| 状态 | fixed |
| 漏洞标题 | krb5: unbounded recursion via an ASN.1-encoded Kerberos message in lib/krb5/asn.1/asn1_encode.c may lead to DoS |
| 威胁等级来源 | nvd |
| 披露时间 | 2020-11-06 08:15:13 |
| 上次修改时间 | 2023-11-07 03:21:07 |

#### 2.1.4.3 漏洞描述
MIT Kerberos 5 (aka krb5) before 1.17.2 and 1.18.x before 1.18.3 allows unbounded recursion via an ASN.1-encoded Kerberos message because the lib/krb5/asn.1/asn1_encode.c support for BER indefinite lengths lacks a recursion limit.

#### 2.1.4.4 相关链接
- https://avd.aquasec.com/nvd/cve-2020-28196
- https://secdb.alpinelinux.org/
- https://access.redhat.com/security/cve/CVE-2020-28196
- https://github.com/krb5/krb5/commit/57415dda6cf04e73ffc3723be518eddfae599bfd
- https://linux.oracle.com/cve/CVE-2020-28196.html
- https://linux.oracle.com/errata/ELSA-2021-9294.html
- https://lists.apache.org/thread.html/r58af02e294bd07f487e2c64ffc0a29b837db5600e33b6e698b9d696b%40%3Cissues.bookkeeper.apache.org%3E
- https://lists.apache.org/thread.html/rf4c02775860db415b4955778a131c2795223f61cb8c6a450893651e4%40%3Cissues.bookkeeper.apache.org%3E
- https://lists.debian.org/debian-lts-announce/2020/11/msg00011.html
- https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/45KKOZQWIIIW5C45PJVGQ32AXBSYNBE7/
- https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/73IGOG6CZAVMVNS4GGRMOLOZ7B6QVA7F/
- https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/KPH2V3WSQTELROZK3GFCPQDOFLKIZ6H5/
- https://nvd.nist.gov/vuln/detail/CVE-2020-28196
- https://security.gentoo.org/glsa/202011-17
- https://security.netapp.com/advisory/ntap-20201202-0001/
- https://security.netapp.com/advisory/ntap-20210513-0002/
- https://ubuntu.com/security/notices/USN-4635-1
- https://www.cve.org/CVERecord?id=CVE-2020-28196
- https://www.debian.org/security/2020/dsa-4795
- https://www.oracle.com//security-alerts/cpujul2021.html
- https://www.oracle.com/security-alerts/cpuApr2021.html
- https://www.oracle.com/security-alerts/cpuapr2022.html

### 2.1.5 CVE-2019-5188:e2fsprogs: Out-of-bounds write in e2fsck/rehash.c
#### 2.1.5.1 软件包信息
| 软件包 URL | pkg:apk/alpine/libcom_err@1.45.2-r1?arch=x86_64&distro=3.10.3 |
|--- | --- |
| 软件包名称 | libcom_err |
| 安装版本 | 1.45.2-r1 |
| 软件包 ID | libcom_err@1.45.2-r1 |
| 修复版本 | 1.45.5-r0 |

#### 2.1.5.2 漏洞信息
| 漏洞编号 | CVE-2019-5188 |
|--- | --- |
| 威胁等级 | MEDIUM |
| 状态 | fixed |
| 漏洞标题 | e2fsprogs: Out-of-bounds write in e2fsck/rehash.c |
| 威胁等级来源 | nvd |
| 披露时间 | 2020-01-08 16:15:11 |
| 上次修改时间 | 2023-11-07 03:11:27 |

#### 2.1.5.3 漏洞描述
A code execution vulnerability exists in the directory rehashing functionality of E2fsprogs e2fsck 1.45.4. A specially crafted ext4 directory can cause an out-of-bounds write on the stack, resulting in code execution. An attacker can corrupt a partition to trigger this vulnerability.

#### 2.1.5.4 相关链接
- https://avd.aquasec.com/nvd/cve-2019-5188
- https://secdb.alpinelinux.org/
- http://lists.opensuse.org/opensuse-security-announce/2020-02/msg00004.html
- https://access.redhat.com/security/cve/CVE-2019-5188
- https://linux.oracle.com/cve/CVE-2019-5188.html
- https://linux.oracle.com/errata/ELSA-2020-4011.html
- https://lists.debian.org/debian-lts-announce/2020/03/msg00030.html
- https://lists.debian.org/debian-lts-announce/2020/07/msg00021.html
- https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/2AKETJ6BREDUHRWQTV35SPGG5C6H7KSI/
- https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/6DOBCYQKCTTWXBLMUPJ5TX3FY7JNCOKY/
- https://nvd.nist.gov/vuln/detail/CVE-2019-5188
- https://security.netapp.com/advisory/ntap-20220506-0001/
- https://talosintelligence.com/vulnerability_reports/TALOS-2019-0973
- https://ubuntu.com/security/notices/USN-4249-1
- https://usn.ubuntu.com/4249-1/
- https://www.cve.org/CVERecord?id=CVE-2019-5188

### 2.1.6 CVE-2020-1967:openssl: Segmentation fault in SSL_check_chain causes denial of service
#### 2.1.6.1 软件包信息
| 软件包 URL | pkg:apk/alpine/libcrypto1.1@1.1.1d-r0?arch=x86_64&distro=3.10.3 |
|--- | --- |
| 软件包名称 | libcrypto1.1 |
| 安装版本 | 1.1.1d-r0 |
| 软件包 ID | libcrypto1.1@1.1.1d-r0 |
| 修复版本 | 1.1.1g-r0 |

#### 2.1.6.2 漏洞信息
| 漏洞编号 | CVE-2020-1967 |
|--- | --- |
| 威胁等级 | HIGH |
| 状态 | fixed |
| 漏洞标题 | openssl: Segmentation fault in SSL_check_chain causes denial of service |
| 威胁等级来源 | nvd |
| 披露时间 | 2020-04-21 14:15:11 |
| 上次修改时间 | 2023-11-07 03:19:39 |

#### 2.1.6.3 漏洞描述
Server or client applications that call the SSL_check_chain() function during or after a TLS 1.3 handshake may crash due to a NULL pointer dereference as a result of incorrect handling of the "signature_algorithms_cert" TLS extension. The crash occurs if an invalid or unrecognised signature algorithm is received from the peer. This could be exploited by a malicious peer in a Denial of Service attack. OpenSSL version 1.1.1d, 1.1.1e, and 1.1.1f are affected by this issue. This issue did not affect OpenSSL versions prior to 1.1.1d. Fixed in OpenSSL 1.1.1g (Affected 1.1.1d-1.1.1f).

#### 2.1.6.4 相关链接
- https://avd.aquasec.com/nvd/cve-2020-1967
- https://secdb.alpinelinux.org/
- http://lists.opensuse.org/opensuse-security-announce/2020-07/msg00004.html
- http://lists.opensuse.org/opensuse-security-announce/2020-07/msg00011.html
- http://packetstormsecurity.com/files/157527/OpenSSL-signature_algorithms_cert-Denial-Of-Service.html
- http://seclists.org/fulldisclosure/2020/May/5
- http://www.openwall.com/lists/oss-security/2020/04/22/2
- https://access.redhat.com/security/cve/CVE-2020-1967
- https://git.openssl.org/gitweb/?p=openssl.git%3Ba=commitdiff%3Bh=eb563247aef3e83dda7679c43f9649270462e5b1
- https://git.openssl.org/gitweb/?p=openssl.git;a=commitdiff;h=eb563247aef3e83dda7679c43f9649270462e5b1
- https://github.com/irsl/CVE-2020-1967
- https://kb.pulsesecure.net/articles/Pulse_Security_Advisories/SA44440
- https://lists.apache.org/thread.html/r66ea9c436da150683432db5fbc8beb8ae01886c6459ac30c2cea7345%40%3Cdev.tomcat.apache.org%3E
- https://lists.apache.org/thread.html/r66ea9c436da150683432db5fbc8beb8ae01886c6459ac30c2cea7345@%3Cdev.tomcat.apache.org%3E
- https://lists.apache.org/thread.html/r94d6ac3f010a38fccf4f432b12180a13fa1cf303559bd805648c9064%40%3Cdev.tomcat.apache.org%3E
- https://lists.apache.org/thread.html/r94d6ac3f010a38fccf4f432b12180a13fa1cf303559bd805648c9064@%3Cdev.tomcat.apache.org%3E
- https://lists.apache.org/thread.html/r9a41e304992ce6aec6585a87842b4f2e692604f5c892c37e3b0587ee%40%3Cdev.tomcat.apache.org%3E
- https://lists.apache.org/thread.html/r9a41e304992ce6aec6585a87842b4f2e692604f5c892c37e3b0587ee@%3Cdev.tomcat.apache.org%3E
- https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/DDHOAATPWJCXRNFMJ2SASDBBNU5RJONY/
- https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/EXDDAOWSAIEFQNBHWYE6PPYFV4QXGMCD/
- https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/XVEP3LAK4JSPRXFO4QF4GG2IVXADV3SO/
- https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/DDHOAATPWJCXRNFMJ2SASDBBNU5RJONY
- https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/EXDDAOWSAIEFQNBHWYE6PPYFV4QXGMCD
- https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/XVEP3LAK4JSPRXFO4QF4GG2IVXADV3SO
- https://nvd.nist.gov/vuln/detail/CVE-2020-1967
- https://rustsec.org/advisories/RUSTSEC-2020-0015.html
- https://security.FreeBSD.org/advisories/FreeBSD-SA-20:11.openssl.asc
- https://security.gentoo.org/glsa/202004-10
- https://security.netapp.com/advisory/ntap-20200424-0003
- https://security.netapp.com/advisory/ntap-20200424-0003/
- https://security.netapp.com/advisory/ntap-20200717-0004
- https://security.netapp.com/advisory/ntap-20200717-0004/
- https://www.cve.org/CVERecord?id=CVE-2020-1967
- https://www.debian.org/security/2020/dsa-4661
- https://www.openssl.org/news/secadv/20200421.txt
- https://www.oracle.com//security-alerts/cpujul2021.html
- https://www.oracle.com/security-alerts/cpuApr2021.html
- https://www.oracle.com/security-alerts/cpujan2021.html
- https://www.oracle.com/security-alerts/cpujul2020.html
- https://www.oracle.com/security-alerts/cpuoct2020.html
- https://www.oracle.com/security-alerts/cpuoct2021.html
- https://www.synology.com/security/advisory/Synology_SA_20_05
- https://www.synology.com/security/advisory/Synology_SA_20_05_OpenSSL
- https://www.tenable.com/security/tns-2020-03
- https://www.tenable.com/security/tns-2020-04
- https://www.tenable.com/security/tns-2020-11
- https://www.tenable.com/security/tns-2021-10

### 2.1.7 CVE-2021-23840:openssl: integer overflow in CipherUpdate
#### 2.1.7.1 软件包信息
| 软件包 URL | pkg:apk/alpine/libcrypto1.1@1.1.1d-r0?arch=x86_64&distro=3.10.3 |
|--- | --- |
| 软件包名称 | libcrypto1.1 |
| 安装版本 | 1.1.1d-r0 |
| 软件包 ID | libcrypto1.1@1.1.1d-r0 |
| 修复版本 | 1.1.1j-r0 |

#### 2.1.7.2 漏洞信息
| 漏洞编号 | CVE-2021-23840 |
|--- | --- |
| 威胁等级 | HIGH |
| 状态 | fixed |
| 漏洞标题 | openssl: integer overflow in CipherUpdate |
| 威胁等级来源 | nvd |
| 披露时间 | 2021-02-16 17:15:13 |
| 上次修改时间 | 2024-06-21 19:15:17 |

#### 2.1.7.3 漏洞描述
Calls to EVP_CipherUpdate, EVP_EncryptUpdate and EVP_DecryptUpdate may overflow the output length argument in some cases where the input length is close to the maximum permissable length for an integer on the platform. In such cases the return value from the function call will be 1 (indicating success), but the output length value will be negative. This could cause applications to behave incorrectly or crash. OpenSSL versions 1.1.1i and below are affected by this issue. Users of these versions should upgrade to OpenSSL 1.1.1j. OpenSSL versions 1.0.2x and below are affected by this issue. However OpenSSL 1.0.2 is out of support and no longer receiving public updates. Premium support customers of OpenSSL 1.0.2 should upgrade to 1.0.2y. Other users should upgrade to 1.1.1j. Fixed in OpenSSL 1.1.1j (Affected 1.1.1-1.1.1i). Fixed in OpenSSL 1.0.2y (Affected 1.0.2-1.0.2x).

#### 2.1.7.4 相关链接
- https://avd.aquasec.com/nvd/cve-2021-23840
- https://secdb.alpinelinux.org/
- https://access.redhat.com/security/cve/CVE-2021-23840
- https://cert-portal.siemens.com/productcert/pdf/ssa-389290.pdf
- https://git.openssl.org/gitweb/?p=openssl.git%3Ba=commitdiff%3Bh=6a51b9e1d0cf0bf8515f7201b68fb0a3482b3dc1
- https://git.openssl.org/gitweb/?p=openssl.git%3Ba=commitdiff%3Bh=9b1129239f3ebb1d1c98ce9ed41d5c9476c47cb2
- https://git.openssl.org/gitweb/?p=openssl.git;a=commitdiff;h=6a51b9e1d0cf0bf8515f7201b68fb0a3482b3dc1
- https://git.openssl.org/gitweb/?p=openssl.git;a=commitdiff;h=9b1129239f3ebb1d1c98ce9ed41d5c9476c47cb2
- https://github.com/alexcrichton/openssl-src-rs
- https://kb.pulsesecure.net/articles/Pulse_Security_Advisories/SA44846
- https://kc.mcafee.com/corporate/index?page=content&id=SB10366
- https://linux.oracle.com/cve/CVE-2021-23840.html
- https://linux.oracle.com/errata/ELSA-2021-9561.html
- https://lists.apache.org/thread.html/r58af02e294bd07f487e2c64ffc0a29b837db5600e33b6e698b9d696b%40%3Cissues.bookkeeper.apache.org%3E
- https://lists.apache.org/thread.html/r58af02e294bd07f487e2c64ffc0a29b837db5600e33b6e698b9d696b@%3Cissues.bookkeeper.apache.org%3E
- https://lists.apache.org/thread.html/rf4c02775860db415b4955778a131c2795223f61cb8c6a450893651e4%40%3Cissues.bookkeeper.apache.org%3E
- https://lists.apache.org/thread.html/rf4c02775860db415b4955778a131c2795223f61cb8c6a450893651e4@%3Cissues.bookkeeper.apache.org%3E
- https://nvd.nist.gov/vuln/detail/CVE-2021-23840
- https://rustsec.org/advisories/RUSTSEC-2021-0057.html
- https://security.gentoo.org/glsa/202103-03
- https://security.netapp.com/advisory/ntap-20210219-0009
- https://security.netapp.com/advisory/ntap-20210219-0009/
- https://security.netapp.com/advisory/ntap-20240621-0006/
- https://ubuntu.com/security/notices/USN-4738-1
- https://ubuntu.com/security/notices/USN-5088-1
- https://ubuntu.com/security/notices/USN-7018-1
- https://www.cve.org/CVERecord?id=CVE-2021-23840
- https://www.debian.org/security/2021/dsa-4855
- https://www.openssl.org/news/secadv/20210216.txt
- https://www.oracle.com//security-alerts/cpujul2021.html
- https://www.oracle.com/security-alerts/cpuApr2021.html
- https://www.oracle.com/security-alerts/cpuapr2022.html
- https://www.oracle.com/security-alerts/cpujan2022.html
- https://www.oracle.com/security-alerts/cpuoct2021.html
- https://www.tenable.com/security/tns-2021-03
- https://www.tenable.com/security/tns-2021-09
- https://www.tenable.com/security/tns-2021-10

### 2.1.8 CVE-2021-3450:openssl: CA certificate check bypass with X509_V_FLAG_X509_STRICT
#### 2.1.8.1 软件包信息
| 软件包 URL | pkg:apk/alpine/libcrypto1.1@1.1.1d-r0?arch=x86_64&distro=3.10.3 |
|--- | --- |
| 软件包名称 | libcrypto1.1 |
| 安装版本 | 1.1.1d-r0 |
| 软件包 ID | libcrypto1.1@1.1.1d-r0 |
| 修复版本 | 1.1.1k-r0 |

#### 2.1.8.2 漏洞信息
| 漏洞编号 | CVE-2021-3450 |
|--- | --- |
| 威胁等级 | HIGH |
| 状态 | fixed |
| 漏洞标题 | openssl: CA certificate check bypass with X509_V_FLAG_X509_STRICT |
| 威胁等级来源 | nvd |
| 披露时间 | 2021-03-25 15:15:13 |
| 上次修改时间 | 2023-11-07 03:38:00 |

#### 2.1.8.3 漏洞描述
The X509_V_FLAG_X509_STRICT flag enables additional security checks of the certificates present in a certificate chain. It is not set by default. Starting from OpenSSL version 1.1.1h a check to disallow certificates in the chain that have explicitly encoded elliptic curve parameters was added as an additional strict check. An error in the implementation of this check meant that the result of a previous check to confirm that certificates in the chain are valid CA certificates was overwritten. This effectively bypasses the check that non-CA certificates must not be able to issue other certificates. If a "purpose" has been configured then there is a subsequent opportunity for checks that the certificate is a valid CA. All of the named "purpose" values implemented in libcrypto perform this check. Therefore, where a purpose is set the certificate chain will still be rejected even when the strict flag has been used. A purpose is set by default in libssl client and server certificate verification routines, but it can be overridden or removed by an application. In order to be affected, an application must explicitly set the X509_V_FLAG_X509_STRICT verification flag and either not set a purpose for the certificate verification or, in the case of TLS client or server applications, override the default purpose. OpenSSL versions 1.1.1h and newer are affected by this issue. Users of these versions should upgrade to OpenSSL 1.1.1k. OpenSSL 1.0.2 is not impacted by this issue. Fixed in OpenSSL 1.1.1k (Affected 1.1.1h-1.1.1j).

#### 2.1.8.4 相关链接
- https://avd.aquasec.com/nvd/cve-2021-3450
- https://secdb.alpinelinux.org/
- http://www.openwall.com/lists/oss-security/2021/03/27/1
- http://www.openwall.com/lists/oss-security/2021/03/27/2
- http://www.openwall.com/lists/oss-security/2021/03/28/3
- http://www.openwall.com/lists/oss-security/2021/03/28/4
- https://access.redhat.com/security/cve/CVE-2021-3450
- https://cert-portal.siemens.com/productcert/pdf/ssa-389290.pdf
- https://git.openssl.org/gitweb/?p=openssl.git%3Ba=commitdiff%3Bh=2a40b7bc7b94dd7de897a74571e7024f0cf0d63b
- https://git.openssl.org/gitweb/?p=openssl.git;a=commitdiff;h=2a40b7bc7b94dd7de897a74571e7024f0cf0d63b
- https://github.com/alexcrichton/openssl-src-rs
- https://kb.pulsesecure.net/articles/Pulse_Security_Advisories/SA44845
- https://kc.mcafee.com/corporate/index?page=content&id=SB10356
- https://linux.oracle.com/cve/CVE-2021-3450.html
- https://linux.oracle.com/errata/ELSA-2021-9151.html
- https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/CCBFLLVQVILIVGZMBJL3IXZGKWQISYNP/
- https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/CCBFLLVQVILIVGZMBJL3IXZGKWQISYNP
- https://mta.openssl.org/pipermail/openssl-announce/2021-March/000198.html
- https://nvd.nist.gov/vuln/detail/CVE-2021-3450
- https://psirt.global.sonicwall.com/vuln-detail/SNWLID-2021-0013
- https://rustsec.org/advisories/RUSTSEC-2021-0056.html
- https://security.FreeBSD.org/advisories/FreeBSD-SA-21:07.openssl.asc
- https://security.gentoo.org/glsa/202103-03
- https://security.netapp.com/advisory/ntap-20210326-0006
- https://security.netapp.com/advisory/ntap-20210326-0006/
- https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-openssl-2021-GHY28dJd
- https://www.cve.org/CVERecord?id=CVE-2021-3450
- https://www.openssl.org/news/secadv/20210325.txt
- https://www.oracle.com//security-alerts/cpujul2021.html
- https://www.oracle.com/security-alerts/cpuApr2021.html
- https://www.oracle.com/security-alerts/cpuapr2022.html
- https://www.oracle.com/security-alerts/cpujul2022.html
- https://www.oracle.com/security-alerts/cpuoct2021.html
- https://www.tenable.com/security/tns-2021-05
- https://www.tenable.com/security/tns-2021-08
- https://www.tenable.com/security/tns-2021-09

### 2.1.9 CVE-2019-1551:openssl: Integer overflow in RSAZ modular exponentiation on x86_64
#### 2.1.9.1 软件包信息
| 软件包 URL | pkg:apk/alpine/libcrypto1.1@1.1.1d-r0?arch=x86_64&distro=3.10.3 |
|--- | --- |
| 软件包名称 | libcrypto1.1 |
| 安装版本 | 1.1.1d-r0 |
| 软件包 ID | libcrypto1.1@1.1.1d-r0 |
| 修复版本 | 1.1.1d-r2 |

#### 2.1.9.2 漏洞信息
| 漏洞编号 | CVE-2019-1551 |
|--- | --- |
| 威胁等级 | MEDIUM |
| 状态 | fixed |
| 漏洞标题 | openssl: Integer overflow in RSAZ modular exponentiation on x86_64 |
| 威胁等级来源 | nvd |
| 披露时间 | 2019-12-06 18:15:12 |
| 上次修改时间 | 2023-11-07 03:08:28 |

#### 2.1.9.3 漏洞描述
There is an overflow bug in the x64_64 Montgomery squaring procedure used in exponentiation with 512-bit moduli. No EC algorithms are affected. Analysis suggests that attacks against 2-prime RSA1024, 3-prime RSA1536, and DSA1024 as a result of this defect would be very difficult to perform and are not believed likely. Attacks against DH512 are considered just feasible. However, for an attack the target would have to re-use the DH512 private key, which is not recommended anyway. Also applications directly using the low level API BN_mod_exp may be affected if they use BN_FLG_CONSTTIME. Fixed in OpenSSL 1.1.1e (Affected 1.1.1-1.1.1d). Fixed in OpenSSL 1.0.2u (Affected 1.0.2-1.0.2t).

#### 2.1.9.4 相关链接
- https://avd.aquasec.com/nvd/cve-2019-1551
- https://secdb.alpinelinux.org/
- http://lists.opensuse.org/opensuse-security-announce/2020-01/msg00030.html
- http://packetstormsecurity.com/files/155754/Slackware-Security-Advisory-openssl-Updates.html
- https://access.redhat.com/security/cve/CVE-2019-1551
- https://git.openssl.org/gitweb/?p=openssl.git%3Ba=commitdiff%3Bh=419102400a2811582a7a3d4a4e317d72e5ce0a8f
- https://git.openssl.org/gitweb/?p=openssl.git%3Ba=commitdiff%3Bh=f1c5eea8a817075d31e43f5876993c6710238c98
- https://github.com/openssl/openssl/pull/10575
- https://linux.oracle.com/cve/CVE-2019-1551.html
- https://linux.oracle.com/errata/ELSA-2020-4514.html
- https://lists.debian.org/debian-lts-announce/2022/03/msg00023.html
- https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/DDHOAATPWJCXRNFMJ2SASDBBNU5RJONY/
- https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/EXDDAOWSAIEFQNBHWYE6PPYFV4QXGMCD/
- https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/XVEP3LAK4JSPRXFO4QF4GG2IVXADV3SO/
- https://nvd.nist.gov/vuln/detail/CVE-2019-1551
- https://seclists.org/bugtraq/2019/Dec/39
- https://seclists.org/bugtraq/2019/Dec/46
- https://security.gentoo.org/glsa/202004-10
- https://security.netapp.com/advisory/ntap-20191210-0001/
- https://ubuntu.com/security/notices/USN-4376-1
- https://ubuntu.com/security/notices/USN-4504-1
- https://usn.ubuntu.com/4376-1/
- https://usn.ubuntu.com/4504-1/
- https://www.cve.org/CVERecord?id=CVE-2019-1551
- https://www.debian.org/security/2019/dsa-4594
- https://www.debian.org/security/2021/dsa-4855
- https://www.openssl.org/news/secadv/20191206.txt
- https://www.oracle.com/security-alerts/cpuApr2021.html
- https://www.oracle.com/security-alerts/cpujan2021.html
- https://www.oracle.com/security-alerts/cpujul2020.html
- https://www.tenable.com/security/tns-2019-09
- https://www.tenable.com/security/tns-2020-03
- https://www.tenable.com/security/tns-2020-11
- https://www.tenable.com/security/tns-2021-10

### 2.1.10 CVE-2020-1971:openssl: EDIPARTYNAME NULL pointer de-reference
#### 2.1.10.1 软件包信息
| 软件包 URL | pkg:apk/alpine/libcrypto1.1@1.1.1d-r0?arch=x86_64&distro=3.10.3 |
|--- | --- |
| 软件包名称 | libcrypto1.1 |
| 安装版本 | 1.1.1d-r0 |
| 软件包 ID | libcrypto1.1@1.1.1d-r0 |
| 修复版本 | 1.1.1i-r0 |

#### 2.1.10.2 漏洞信息
| 漏洞编号 | CVE-2020-1971 |
|--- | --- |
| 威胁等级 | MEDIUM |
| 状态 | fixed |
| 漏洞标题 | openssl: EDIPARTYNAME NULL pointer de-reference |
| 威胁等级来源 | nvd |
| 披露时间 | 2020-12-08 16:15:11 |
| 上次修改时间 | 2024-06-21 19:15:16 |

#### 2.1.10.3 漏洞描述
The X.509 GeneralName type is a generic type for representing different types of names. One of those name types is known as EDIPartyName. OpenSSL provides a function GENERAL_NAME_cmp which compares different instances of a GENERAL_NAME to see if they are equal or not. This function behaves incorrectly when both GENERAL_NAMEs contain an EDIPARTYNAME. A NULL pointer dereference and a crash may occur leading to a possible denial of service attack. OpenSSL itself uses the GENERAL_NAME_cmp function for two purposes: 1) Comparing CRL distribution point names between an available CRL and a CRL distribution point embedded in an X509 certificate 2) When verifying that a timestamp response token signer matches the timestamp authority name (exposed via the API functions TS_RESP_verify_response and TS_RESP_verify_token) If an attacker can control both items being compared then that attacker could trigger a crash. For example if the attacker can trick a client or server into checking a malicious certificate against a malicious CRL then this may occur. Note that some applications automatically download CRLs based on a URL embedded in a certificate. This checking happens prior to the signatures on the certificate and CRL being verified. OpenSSL's s_server, s_client and verify tools have support for the "-crl_download" option which implements automatic CRL downloading and this attack has been demonstrated to work against those tools. Note that an unrelated bug means that affected versions of OpenSSL cannot parse or construct correct encodings of EDIPARTYNAME. However it is possible to construct a malformed EDIPARTYNAME that OpenSSL's parser will accept and hence trigger this attack. All OpenSSL 1.1.1 and 1.0.2 versions are affected by this issue. Other OpenSSL releases are out of support and have not been checked. Fixed in OpenSSL 1.1.1i (Affected 1.1.1-1.1.1h). Fixed in OpenSSL 1.0.2x (Affected 1.0.2-1.0.2w).

#### 2.1.10.4 相关链接
- https://avd.aquasec.com/nvd/cve-2020-1971
- https://secdb.alpinelinux.org/
- http://www.openwall.com/lists/oss-security/2021/09/14/2
- https://access.redhat.com/security/cve/CVE-2020-1971
- https://cert-portal.siemens.com/productcert/pdf/ssa-389290.pdf
- https://git.openssl.org/gitweb/?p=openssl.git%3Ba=commitdiff%3Bh=2154ab83e14ede338d2ede9bbe5cdfce5d5a6c9e
- https://git.openssl.org/gitweb/?p=openssl.git%3Ba=commitdiff%3Bh=f960d81215ebf3f65e03d4d5d857fb9b666d6920
- https://kb.pulsesecure.net/articles/Pulse_Security_Advisories/SA44676
- https://linux.oracle.com/cve/CVE-2020-1971.html
- https://linux.oracle.com/errata/ELSA-2021-9150.html
- https://lists.apache.org/thread.html/r63c6f2dd363d9b514d0a4bcf624580616a679898cc14c109a49b750c%40%3Cdev.tomcat.apache.org%3E
- https://lists.apache.org/thread.html/rbb769f771711fb274e0a4acb1b5911c8aab544a6ac5e8c12d40c5143%40%3Ccommits.pulsar.apache.org%3E
- https://lists.debian.org/debian-lts-announce/2020/12/msg00020.html
- https://lists.debian.org/debian-lts-announce/2020/12/msg00021.html
- https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/DGSI34Y5LQ5RYXN4M2I5ZQT65LFVDOUU/
- https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/PWPSSZNZOBJU2YR6Z4TGHXKYW3YP5QG7/
- https://nvd.nist.gov/vuln/detail/CVE-2020-1971
- https://security.FreeBSD.org/advisories/FreeBSD-SA-20:33.openssl.asc
- https://security.gentoo.org/glsa/202012-13
- https://security.netapp.com/advisory/ntap-20201218-0005/
- https://security.netapp.com/advisory/ntap-20210513-0002/
- https://security.netapp.com/advisory/ntap-20240621-0006/
- https://ubuntu.com/security/notices/USN-4662-1
- https://ubuntu.com/security/notices/USN-4745-1
- https://www.cve.org/CVERecord?id=CVE-2020-1971
- https://www.debian.org/security/2020/dsa-4807
- https://www.openssl.org/news/secadv/20201208.txt
- https://www.oracle.com//security-alerts/cpujul2021.html
- https://www.oracle.com/security-alerts/cpuApr2021.html
- https://www.oracle.com/security-alerts/cpuapr2022.html
- https://www.oracle.com/security-alerts/cpujan2021.html
- https://www.oracle.com/security-alerts/cpuoct2021.html
- https://www.tenable.com/security/tns-2020-11
- https://www.tenable.com/security/tns-2021-09
- https://www.tenable.com/security/tns-2021-10

### 2.1.11 CVE-2021-23841:openssl: NULL pointer dereference in X509_issuer_and_serial_hash()
#### 2.1.11.1 软件包信息
| 软件包 URL | pkg:apk/alpine/libcrypto1.1@1.1.1d-r0?arch=x86_64&distro=3.10.3 |
|--- | --- |
| 软件包名称 | libcrypto1.1 |
| 安装版本 | 1.1.1d-r0 |
| 软件包 ID | libcrypto1.1@1.1.1d-r0 |
| 修复版本 | 1.1.1j-r0 |

#### 2.1.11.2 漏洞信息
| 漏洞编号 | CVE-2021-23841 |
|--- | --- |
| 威胁等级 | MEDIUM |
| 状态 | fixed |
| 漏洞标题 | openssl: NULL pointer dereference in X509_issuer_and_serial_hash() |
| 威胁等级来源 | nvd |
| 披露时间 | 2021-02-16 17:15:13 |
| 上次修改时间 | 2024-06-21 19:15:17 |

#### 2.1.11.3 漏洞描述
The OpenSSL public API function X509_issuer_and_serial_hash() attempts to create a unique hash value based on the issuer and serial number data contained within an X509 certificate. However it fails to correctly handle any errors that may occur while parsing the issuer field (which might occur if the issuer field is maliciously constructed). This may subsequently result in a NULL pointer deref and a crash leading to a potential denial of service attack. The function X509_issuer_and_serial_hash() is never directly called by OpenSSL itself so applications are only vulnerable if they use this function directly and they use it on certificates that may have been obtained from untrusted sources. OpenSSL versions 1.1.1i and below are affected by this issue. Users of these versions should upgrade to OpenSSL 1.1.1j. OpenSSL versions 1.0.2x and below are affected by this issue. However OpenSSL 1.0.2 is out of support and no longer receiving public updates. Premium support customers of OpenSSL 1.0.2 should upgrade to 1.0.2y. Other users should upgrade to 1.1.1j. Fixed in OpenSSL 1.1.1j (Affected 1.1.1-1.1.1i). Fixed in OpenSSL 1.0.2y (Affected 1.0.2-1.0.2x).

#### 2.1.11.4 相关链接
- https://avd.aquasec.com/nvd/cve-2021-23841
- https://secdb.alpinelinux.org/
- http://seclists.org/fulldisclosure/2021/May/67
- http://seclists.org/fulldisclosure/2021/May/68
- http://seclists.org/fulldisclosure/2021/May/70
- https://access.redhat.com/security/cve/CVE-2021-23841
- https://cert-portal.siemens.com/productcert/pdf/ssa-637483.pdf
- https://git.openssl.org/gitweb/?p=openssl.git%3Ba=commitdiff%3Bh=122a19ab48091c657f7cb1fb3af9fc07bd557bbf
- https://git.openssl.org/gitweb/?p=openssl.git%3Ba=commitdiff%3Bh=8252ee4d90f3f2004d3d0aeeed003ad49c9a7807
- https://git.openssl.org/gitweb/?p=openssl.git;a=commitdiff;h=122a19ab48091c657f7cb1fb3af9fc07bd557bbf
- https://git.openssl.org/gitweb/?p=openssl.git;a=commitdiff;h=6a51b9e1d0cf0bf8515f7201b68fb0a3482b3dc1
- https://git.openssl.org/gitweb/?p=openssl.git;a=commitdiff;h=8252ee4d90f3f2004d3d0aeeed003ad49c9a7807
- https://git.openssl.org/gitweb/?p=openssl.git;a=commitdiff;h=9b1129239f3ebb1d1c98ce9ed41d5c9476c47cb2
- https://github.com/alexcrichton/openssl-src-rs
- https://kb.pulsesecure.net/articles/Pulse_Security_Advisories/SA44846
- https://linux.oracle.com/cve/CVE-2021-23841.html
- https://linux.oracle.com/errata/ELSA-2021-9561.html
- https://nvd.nist.gov/vuln/detail/CVE-2021-23841
- https://rustsec.org/advisories/RUSTSEC-2021-0058
- https://rustsec.org/advisories/RUSTSEC-2021-0058.html
- https://security.gentoo.org/glsa/202103-03
- https://security.netapp.com/advisory/ntap-20210219-0009
- https://security.netapp.com/advisory/ntap-20210219-0009/
- https://security.netapp.com/advisory/ntap-20210513-0002
- https://security.netapp.com/advisory/ntap-20210513-0002/
- https://security.netapp.com/advisory/ntap-20240621-0006/
- https://support.apple.com/kb/HT212528
- https://support.apple.com/kb/HT212529
- https://support.apple.com/kb/HT212534
- https://ubuntu.com/security/notices/USN-4738-1
- https://ubuntu.com/security/notices/USN-4745-1
- https://www.cve.org/CVERecord?id=CVE-2021-23841
- https://www.debian.org/security/2021/dsa-4855
- https://www.openssl.org/news/secadv/20210216.txt
- https://www.oracle.com//security-alerts/cpujul2021.html
- https://www.oracle.com/security-alerts/cpuApr2021.html
- https://www.oracle.com/security-alerts/cpuapr2022.html
- https://www.oracle.com/security-alerts/cpuoct2021.html
- https://www.tenable.com/security/tns-2021-03
- https://www.tenable.com/security/tns-2021-09

### 2.1.12 CVE-2021-3449:openssl: NULL pointer dereference in signature_algorithms processing
#### 2.1.12.1 软件包信息
| 软件包 URL | pkg:apk/alpine/libcrypto1.1@1.1.1d-r0?arch=x86_64&distro=3.10.3 |
|--- | --- |
| 软件包名称 | libcrypto1.1 |
| 安装版本 | 1.1.1d-r0 |
| 软件包 ID | libcrypto1.1@1.1.1d-r0 |
| 修复版本 | 1.1.1k-r0 |

#### 2.1.12.2 漏洞信息
| 漏洞编号 | CVE-2021-3449 |
|--- | --- |
| 威胁等级 | MEDIUM |
| 状态 | fixed |
| 漏洞标题 | openssl: NULL pointer dereference in signature_algorithms processing |
| 威胁等级来源 | nvd |
| 披露时间 | 2021-03-25 15:15:13 |
| 上次修改时间 | 2024-06-21 19:15:19 |

#### 2.1.12.3 漏洞描述
An OpenSSL TLS server may crash if sent a maliciously crafted renegotiation ClientHello message from a client. If a TLSv1.2 renegotiation ClientHello omits the signature_algorithms extension (where it was present in the initial ClientHello), but includes a signature_algorithms_cert extension then a NULL pointer dereference will result, leading to a crash and a denial of service attack. A server is only vulnerable if it has TLSv1.2 and renegotiation enabled (which is the default configuration). OpenSSL TLS clients are not impacted by this issue. All OpenSSL 1.1.1 versions are affected by this issue. Users of these versions should upgrade to OpenSSL 1.1.1k. OpenSSL 1.0.2 is not impacted by this issue. Fixed in OpenSSL 1.1.1k (Affected 1.1.1-1.1.1j).

#### 2.1.12.4 相关链接
- https://avd.aquasec.com/nvd/cve-2021-3449
- https://secdb.alpinelinux.org/
- http://www.openwall.com/lists/oss-security/2021/03/27/1
- http://www.openwall.com/lists/oss-security/2021/03/27/2
- http://www.openwall.com/lists/oss-security/2021/03/28/3
- http://www.openwall.com/lists/oss-security/2021/03/28/4
- https://access.redhat.com/security/cve/CVE-2021-3449
- https://cert-portal.siemens.com/productcert/pdf/ssa-389290.pdf
- https://cert-portal.siemens.com/productcert/pdf/ssa-772220.pdf
- https://git.openssl.org/gitweb/?p=openssl.git%3Ba=commitdiff%3Bh=fb9fa6b51defd48157eeb207f52181f735d96148
- https://git.openssl.org/gitweb/?p=openssl.git;a=commitdiff;h=fb9fa6b51defd48157eeb207f52181f735d96148
- https://github.com/alexcrichton/openssl-src-rs
- https://github.com/nodejs/node/pull/38083
- https://kb.pulsesecure.net/articles/Pulse_Security_Advisories/SA44845
- https://kc.mcafee.com/corporate/index?page=content&id=SB10356
- https://linux.oracle.com/cve/CVE-2021-3449.html
- https://linux.oracle.com/errata/ELSA-2021-9151.html
- https://lists.debian.org/debian-lts-announce/2021/08/msg00029.html
- https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/CCBFLLVQVILIVGZMBJL3IXZGKWQISYNP/
- https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/CCBFLLVQVILIVGZMBJL3IXZGKWQISYNP
- https://nvd.nist.gov/vuln/detail/CVE-2021-3449
- https://psirt.global.sonicwall.com/vuln-detail/SNWLID-2021-0013
- https://rustsec.org/advisories/RUSTSEC-2021-0055
- https://rustsec.org/advisories/RUSTSEC-2021-0055.html
- https://security.FreeBSD.org/advisories/FreeBSD-SA-21:07.openssl.asc
- https://security.gentoo.org/glsa/202103-03
- https://security.netapp.com/advisory/ntap-20210326-0006
- https://security.netapp.com/advisory/ntap-20210326-0006/
- https://security.netapp.com/advisory/ntap-20210513-0002
- https://security.netapp.com/advisory/ntap-20210513-0002/
- https://security.netapp.com/advisory/ntap-20240621-0006/
- https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-openssl-2021-GHY28dJd
- https://ubuntu.com/security/notices/USN-4891-1
- https://ubuntu.com/security/notices/USN-5038-1
- https://www.cve.org/CVERecord?id=CVE-2021-3449
- https://www.debian.org/security/2021/dsa-4875
- https://www.openssl.org/news/secadv/20210325.txt
- https://www.oracle.com//security-alerts/cpujul2021.html
- https://www.oracle.com/security-alerts/cpuApr2021.html
- https://www.oracle.com/security-alerts/cpuapr2022.html
- https://www.oracle.com/security-alerts/cpujul2022.html
- https://www.oracle.com/security-alerts/cpuoct2021.html
- https://www.tenable.com/security/tns-2021-05
- https://www.tenable.com/security/tns-2021-06
- https://www.tenable.com/security/tns-2021-09
- https://www.tenable.com/security/tns-2021-10

### 2.1.13 CVE-2021-23839:openssl: incorrect SSLv2 rollback protection
#### 2.1.13.1 软件包信息
| 软件包 URL | pkg:apk/alpine/libcrypto1.1@1.1.1d-r0?arch=x86_64&distro=3.10.3 |
|--- | --- |
| 软件包名称 | libcrypto1.1 |
| 安装版本 | 1.1.1d-r0 |
| 软件包 ID | libcrypto1.1@1.1.1d-r0 |
| 修复版本 | 1.1.1j-r0 |

#### 2.1.13.2 漏洞信息
| 漏洞编号 | CVE-2021-23839 |
|--- | --- |
| 威胁等级 | LOW |
| 状态 | fixed |
| 漏洞标题 | openssl: incorrect SSLv2 rollback protection |
| 威胁等级来源 | nvd |
| 披露时间 | 2021-02-16 17:15:13 |
| 上次修改时间 | 2024-06-21 19:15:16 |

#### 2.1.13.3 漏洞描述
OpenSSL 1.0.2 supports SSLv2. If a client attempts to negotiate SSLv2 with a server that is configured to support both SSLv2 and more recent SSL and TLS versions then a check is made for a version rollback attack when unpadding an RSA signature. Clients that support SSL or TLS versions greater than SSLv2 are supposed to use a special form of padding. A server that supports greater than SSLv2 is supposed to reject connection attempts from a client where this special form of padding is present, because this indicates that a version rollback has occurred (i.e. both client and server support greater than SSLv2, and yet this is the version that is being requested). The implementation of this padding check inverted the logic so that the connection attempt is accepted if the padding is present, and rejected if it is absent. This means that such as server will accept a connection if a version rollback attack has occurred. Further the server will erroneously reject a connection if a normal SSLv2 connection attempt is made. Only OpenSSL 1.0.2 servers from version 1.0.2s to 1.0.2x are affected by this issue. In order to be vulnerable a 1.0.2 server must: 1) have configured SSLv2 support at compile time (this is off by default), 2) have configured SSLv2 support at runtime (this is off by default), 3) have configured SSLv2 ciphersuites (these are not in the default ciphersuite list) OpenSSL 1.1.1 does not have SSLv2 support and therefore is not vulnerable to this issue. The underlying error is in the implementation of the RSA_padding_check_SSLv23() function. This also affects the RSA_SSLV23_PADDING padding mode used by various other functions. Although 1.1.1 does not support SSLv2 the RSA_padding_check_SSLv23() function still exists, as does the RSA_SSLV23_PADDING padding mode. Applications that directly call that function or use that padding mode will encounter this issue. However since there is no support for the SSLv2 protocol in 1.1.1 this is considered a bug and not a security issue in that version. OpenSSL 1.0.2 is out of support and no longer receiving public updates. Premium support customers of OpenSSL 1.0.2 should upgrade to 1.0.2y. Other users should upgrade to 1.1.1j. Fixed in OpenSSL 1.0.2y (Affected 1.0.2s-1.0.2x).

#### 2.1.13.4 相关链接
- https://avd.aquasec.com/nvd/cve-2021-23839
- https://secdb.alpinelinux.org/
- https://access.redhat.com/security/cve/CVE-2021-23839
- https://cert-portal.siemens.com/productcert/pdf/ssa-637483.pdf
- https://git.openssl.org/gitweb/?p=openssl.git%3Ba=commitdiff%3Bh=30919ab80a478f2d81f2e9acdcca3fa4740cd547
- https://kb.pulsesecure.net/articles/Pulse_Security_Advisories/SA44846
- https://nvd.nist.gov/vuln/detail/CVE-2021-23839
- https://security.netapp.com/advisory/ntap-20210219-0009/
- https://security.netapp.com/advisory/ntap-20240621-0006/
- https://www.cve.org/CVERecord?id=CVE-2021-23839
- https://www.openssl.org/news/secadv/20210216.txt
- https://www.oracle.com//security-alerts/cpujul2021.html
- https://www.oracle.com/security-alerts/cpuApr2021.html
- https://www.oracle.com/security-alerts/cpuapr2022.html
- https://www.oracle.com/security-alerts/cpuoct2021.html

### 2.1.14 CVE-2020-1967:openssl: Segmentation fault in SSL_check_chain causes denial of service
#### 2.1.14.1 软件包信息
| 软件包 URL | pkg:apk/alpine/libssl1.1@1.1.1d-r0?arch=x86_64&distro=3.10.3 |
|--- | --- |
| 软件包名称 | libssl1.1 |
| 安装版本 | 1.1.1d-r0 |
| 软件包 ID | libssl1.1@1.1.1d-r0 |
| 修复版本 | 1.1.1g-r0 |

#### 2.1.14.2 漏洞信息
| 漏洞编号 | CVE-2020-1967 |
|--- | --- |
| 威胁等级 | HIGH |
| 状态 | fixed |
| 漏洞标题 | openssl: Segmentation fault in SSL_check_chain causes denial of service |
| 威胁等级来源 | nvd |
| 披露时间 | 2020-04-21 14:15:11 |
| 上次修改时间 | 2023-11-07 03:19:39 |

#### 2.1.14.3 漏洞描述
Server or client applications that call the SSL_check_chain() function during or after a TLS 1.3 handshake may crash due to a NULL pointer dereference as a result of incorrect handling of the "signature_algorithms_cert" TLS extension. The crash occurs if an invalid or unrecognised signature algorithm is received from the peer. This could be exploited by a malicious peer in a Denial of Service attack. OpenSSL version 1.1.1d, 1.1.1e, and 1.1.1f are affected by this issue. This issue did not affect OpenSSL versions prior to 1.1.1d. Fixed in OpenSSL 1.1.1g (Affected 1.1.1d-1.1.1f).

#### 2.1.14.4 相关链接
- https://avd.aquasec.com/nvd/cve-2020-1967
- https://secdb.alpinelinux.org/
- http://lists.opensuse.org/opensuse-security-announce/2020-07/msg00004.html
- http://lists.opensuse.org/opensuse-security-announce/2020-07/msg00011.html
- http://packetstormsecurity.com/files/157527/OpenSSL-signature_algorithms_cert-Denial-Of-Service.html
- http://seclists.org/fulldisclosure/2020/May/5
- http://www.openwall.com/lists/oss-security/2020/04/22/2
- https://access.redhat.com/security/cve/CVE-2020-1967
- https://git.openssl.org/gitweb/?p=openssl.git%3Ba=commitdiff%3Bh=eb563247aef3e83dda7679c43f9649270462e5b1
- https://git.openssl.org/gitweb/?p=openssl.git;a=commitdiff;h=eb563247aef3e83dda7679c43f9649270462e5b1
- https://github.com/irsl/CVE-2020-1967
- https://kb.pulsesecure.net/articles/Pulse_Security_Advisories/SA44440
- https://lists.apache.org/thread.html/r66ea9c436da150683432db5fbc8beb8ae01886c6459ac30c2cea7345%40%3Cdev.tomcat.apache.org%3E
- https://lists.apache.org/thread.html/r66ea9c436da150683432db5fbc8beb8ae01886c6459ac30c2cea7345@%3Cdev.tomcat.apache.org%3E
- https://lists.apache.org/thread.html/r94d6ac3f010a38fccf4f432b12180a13fa1cf303559bd805648c9064%40%3Cdev.tomcat.apache.org%3E
- https://lists.apache.org/thread.html/r94d6ac3f010a38fccf4f432b12180a13fa1cf303559bd805648c9064@%3Cdev.tomcat.apache.org%3E
- https://lists.apache.org/thread.html/r9a41e304992ce6aec6585a87842b4f2e692604f5c892c37e3b0587ee%40%3Cdev.tomcat.apache.org%3E
- https://lists.apache.org/thread.html/r9a41e304992ce6aec6585a87842b4f2e692604f5c892c37e3b0587ee@%3Cdev.tomcat.apache.org%3E
- https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/DDHOAATPWJCXRNFMJ2SASDBBNU5RJONY/
- https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/EXDDAOWSAIEFQNBHWYE6PPYFV4QXGMCD/
- https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/XVEP3LAK4JSPRXFO4QF4GG2IVXADV3SO/
- https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/DDHOAATPWJCXRNFMJ2SASDBBNU5RJONY
- https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/EXDDAOWSAIEFQNBHWYE6PPYFV4QXGMCD
- https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/XVEP3LAK4JSPRXFO4QF4GG2IVXADV3SO
- https://nvd.nist.gov/vuln/detail/CVE-2020-1967
- https://rustsec.org/advisories/RUSTSEC-2020-0015.html
- https://security.FreeBSD.org/advisories/FreeBSD-SA-20:11.openssl.asc
- https://security.gentoo.org/glsa/202004-10
- https://security.netapp.com/advisory/ntap-20200424-0003
- https://security.netapp.com/advisory/ntap-20200424-0003/
- https://security.netapp.com/advisory/ntap-20200717-0004
- https://security.netapp.com/advisory/ntap-20200717-0004/
- https://www.cve.org/CVERecord?id=CVE-2020-1967
- https://www.debian.org/security/2020/dsa-4661
- https://www.openssl.org/news/secadv/20200421.txt
- https://www.oracle.com//security-alerts/cpujul2021.html
- https://www.oracle.com/security-alerts/cpuApr2021.html
- https://www.oracle.com/security-alerts/cpujan2021.html
- https://www.oracle.com/security-alerts/cpujul2020.html
- https://www.oracle.com/security-alerts/cpuoct2020.html
- https://www.oracle.com/security-alerts/cpuoct2021.html
- https://www.synology.com/security/advisory/Synology_SA_20_05
- https://www.synology.com/security/advisory/Synology_SA_20_05_OpenSSL
- https://www.tenable.com/security/tns-2020-03
- https://www.tenable.com/security/tns-2020-04
- https://www.tenable.com/security/tns-2020-11
- https://www.tenable.com/security/tns-2021-10

### 2.1.15 CVE-2021-23840:openssl: integer overflow in CipherUpdate
#### 2.1.15.1 软件包信息
| 软件包 URL | pkg:apk/alpine/libssl1.1@1.1.1d-r0?arch=x86_64&distro=3.10.3 |
|--- | --- |
| 软件包名称 | libssl1.1 |
| 安装版本 | 1.1.1d-r0 |
| 软件包 ID | libssl1.1@1.1.1d-r0 |
| 修复版本 | 1.1.1j-r0 |

#### 2.1.15.2 漏洞信息
| 漏洞编号 | CVE-2021-23840 |
|--- | --- |
| 威胁等级 | HIGH |
| 状态 | fixed |
| 漏洞标题 | openssl: integer overflow in CipherUpdate |
| 威胁等级来源 | nvd |
| 披露时间 | 2021-02-16 17:15:13 |
| 上次修改时间 | 2024-06-21 19:15:17 |

#### 2.1.15.3 漏洞描述
Calls to EVP_CipherUpdate, EVP_EncryptUpdate and EVP_DecryptUpdate may overflow the output length argument in some cases where the input length is close to the maximum permissable length for an integer on the platform. In such cases the return value from the function call will be 1 (indicating success), but the output length value will be negative. This could cause applications to behave incorrectly or crash. OpenSSL versions 1.1.1i and below are affected by this issue. Users of these versions should upgrade to OpenSSL 1.1.1j. OpenSSL versions 1.0.2x and below are affected by this issue. However OpenSSL 1.0.2 is out of support and no longer receiving public updates. Premium support customers of OpenSSL 1.0.2 should upgrade to 1.0.2y. Other users should upgrade to 1.1.1j. Fixed in OpenSSL 1.1.1j (Affected 1.1.1-1.1.1i). Fixed in OpenSSL 1.0.2y (Affected 1.0.2-1.0.2x).

#### 2.1.15.4 相关链接
- https://avd.aquasec.com/nvd/cve-2021-23840
- https://secdb.alpinelinux.org/
- https://access.redhat.com/security/cve/CVE-2021-23840
- https://cert-portal.siemens.com/productcert/pdf/ssa-389290.pdf
- https://git.openssl.org/gitweb/?p=openssl.git%3Ba=commitdiff%3Bh=6a51b9e1d0cf0bf8515f7201b68fb0a3482b3dc1
- https://git.openssl.org/gitweb/?p=openssl.git%3Ba=commitdiff%3Bh=9b1129239f3ebb1d1c98ce9ed41d5c9476c47cb2
- https://git.openssl.org/gitweb/?p=openssl.git;a=commitdiff;h=6a51b9e1d0cf0bf8515f7201b68fb0a3482b3dc1
- https://git.openssl.org/gitweb/?p=openssl.git;a=commitdiff;h=9b1129239f3ebb1d1c98ce9ed41d5c9476c47cb2
- https://github.com/alexcrichton/openssl-src-rs
- https://kb.pulsesecure.net/articles/Pulse_Security_Advisories/SA44846
- https://kc.mcafee.com/corporate/index?page=content&id=SB10366
- https://linux.oracle.com/cve/CVE-2021-23840.html
- https://linux.oracle.com/errata/ELSA-2021-9561.html
- https://lists.apache.org/thread.html/r58af02e294bd07f487e2c64ffc0a29b837db5600e33b6e698b9d696b%40%3Cissues.bookkeeper.apache.org%3E
- https://lists.apache.org/thread.html/r58af02e294bd07f487e2c64ffc0a29b837db5600e33b6e698b9d696b@%3Cissues.bookkeeper.apache.org%3E
- https://lists.apache.org/thread.html/rf4c02775860db415b4955778a131c2795223f61cb8c6a450893651e4%40%3Cissues.bookkeeper.apache.org%3E
- https://lists.apache.org/thread.html/rf4c02775860db415b4955778a131c2795223f61cb8c6a450893651e4@%3Cissues.bookkeeper.apache.org%3E
- https://nvd.nist.gov/vuln/detail/CVE-2021-23840
- https://rustsec.org/advisories/RUSTSEC-2021-0057.html
- https://security.gentoo.org/glsa/202103-03
- https://security.netapp.com/advisory/ntap-20210219-0009
- https://security.netapp.com/advisory/ntap-20210219-0009/
- https://security.netapp.com/advisory/ntap-20240621-0006/
- https://ubuntu.com/security/notices/USN-4738-1
- https://ubuntu.com/security/notices/USN-5088-1
- https://ubuntu.com/security/notices/USN-7018-1
- https://www.cve.org/CVERecord?id=CVE-2021-23840
- https://www.debian.org/security/2021/dsa-4855
- https://www.openssl.org/news/secadv/20210216.txt
- https://www.oracle.com//security-alerts/cpujul2021.html
- https://www.oracle.com/security-alerts/cpuApr2021.html
- https://www.oracle.com/security-alerts/cpuapr2022.html
- https://www.oracle.com/security-alerts/cpujan2022.html
- https://www.oracle.com/security-alerts/cpuoct2021.html
- https://www.tenable.com/security/tns-2021-03
- https://www.tenable.com/security/tns-2021-09
- https://www.tenable.com/security/tns-2021-10

### 2.1.16 CVE-2021-3450:openssl: CA certificate check bypass with X509_V_FLAG_X509_STRICT
#### 2.1.16.1 软件包信息
| 软件包 URL | pkg:apk/alpine/libssl1.1@1.1.1d-r0?arch=x86_64&distro=3.10.3 |
|--- | --- |
| 软件包名称 | libssl1.1 |
| 安装版本 | 1.1.1d-r0 |
| 软件包 ID | libssl1.1@1.1.1d-r0 |
| 修复版本 | 1.1.1k-r0 |

#### 2.1.16.2 漏洞信息
| 漏洞编号 | CVE-2021-3450 |
|--- | --- |
| 威胁等级 | HIGH |
| 状态 | fixed |
| 漏洞标题 | openssl: CA certificate check bypass with X509_V_FLAG_X509_STRICT |
| 威胁等级来源 | nvd |
| 披露时间 | 2021-03-25 15:15:13 |
| 上次修改时间 | 2023-11-07 03:38:00 |

#### 2.1.16.3 漏洞描述
The X509_V_FLAG_X509_STRICT flag enables additional security checks of the certificates present in a certificate chain. It is not set by default. Starting from OpenSSL version 1.1.1h a check to disallow certificates in the chain that have explicitly encoded elliptic curve parameters was added as an additional strict check. An error in the implementation of this check meant that the result of a previous check to confirm that certificates in the chain are valid CA certificates was overwritten. This effectively bypasses the check that non-CA certificates must not be able to issue other certificates. If a "purpose" has been configured then there is a subsequent opportunity for checks that the certificate is a valid CA. All of the named "purpose" values implemented in libcrypto perform this check. Therefore, where a purpose is set the certificate chain will still be rejected even when the strict flag has been used. A purpose is set by default in libssl client and server certificate verification routines, but it can be overridden or removed by an application. In order to be affected, an application must explicitly set the X509_V_FLAG_X509_STRICT verification flag and either not set a purpose for the certificate verification or, in the case of TLS client or server applications, override the default purpose. OpenSSL versions 1.1.1h and newer are affected by this issue. Users of these versions should upgrade to OpenSSL 1.1.1k. OpenSSL 1.0.2 is not impacted by this issue. Fixed in OpenSSL 1.1.1k (Affected 1.1.1h-1.1.1j).

#### 2.1.16.4 相关链接
- https://avd.aquasec.com/nvd/cve-2021-3450
- https://secdb.alpinelinux.org/
- http://www.openwall.com/lists/oss-security/2021/03/27/1
- http://www.openwall.com/lists/oss-security/2021/03/27/2
- http://www.openwall.com/lists/oss-security/2021/03/28/3
- http://www.openwall.com/lists/oss-security/2021/03/28/4
- https://access.redhat.com/security/cve/CVE-2021-3450
- https://cert-portal.siemens.com/productcert/pdf/ssa-389290.pdf
- https://git.openssl.org/gitweb/?p=openssl.git%3Ba=commitdiff%3Bh=2a40b7bc7b94dd7de897a74571e7024f0cf0d63b
- https://git.openssl.org/gitweb/?p=openssl.git;a=commitdiff;h=2a40b7bc7b94dd7de897a74571e7024f0cf0d63b
- https://github.com/alexcrichton/openssl-src-rs
- https://kb.pulsesecure.net/articles/Pulse_Security_Advisories/SA44845
- https://kc.mcafee.com/corporate/index?page=content&id=SB10356
- https://linux.oracle.com/cve/CVE-2021-3450.html
- https://linux.oracle.com/errata/ELSA-2021-9151.html
- https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/CCBFLLVQVILIVGZMBJL3IXZGKWQISYNP/
- https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/CCBFLLVQVILIVGZMBJL3IXZGKWQISYNP
- https://mta.openssl.org/pipermail/openssl-announce/2021-March/000198.html
- https://nvd.nist.gov/vuln/detail/CVE-2021-3450
- https://psirt.global.sonicwall.com/vuln-detail/SNWLID-2021-0013
- https://rustsec.org/advisories/RUSTSEC-2021-0056.html
- https://security.FreeBSD.org/advisories/FreeBSD-SA-21:07.openssl.asc
- https://security.gentoo.org/glsa/202103-03
- https://security.netapp.com/advisory/ntap-20210326-0006
- https://security.netapp.com/advisory/ntap-20210326-0006/
- https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-openssl-2021-GHY28dJd
- https://www.cve.org/CVERecord?id=CVE-2021-3450
- https://www.openssl.org/news/secadv/20210325.txt
- https://www.oracle.com//security-alerts/cpujul2021.html
- https://www.oracle.com/security-alerts/cpuApr2021.html
- https://www.oracle.com/security-alerts/cpuapr2022.html
- https://www.oracle.com/security-alerts/cpujul2022.html
- https://www.oracle.com/security-alerts/cpuoct2021.html
- https://www.tenable.com/security/tns-2021-05
- https://www.tenable.com/security/tns-2021-08
- https://www.tenable.com/security/tns-2021-09

### 2.1.17 CVE-2019-1551:openssl: Integer overflow in RSAZ modular exponentiation on x86_64
#### 2.1.17.1 软件包信息
| 软件包 URL | pkg:apk/alpine/libssl1.1@1.1.1d-r0?arch=x86_64&distro=3.10.3 |
|--- | --- |
| 软件包名称 | libssl1.1 |
| 安装版本 | 1.1.1d-r0 |
| 软件包 ID | libssl1.1@1.1.1d-r0 |
| 修复版本 | 1.1.1d-r2 |

#### 2.1.17.2 漏洞信息
| 漏洞编号 | CVE-2019-1551 |
|--- | --- |
| 威胁等级 | MEDIUM |
| 状态 | fixed |
| 漏洞标题 | openssl: Integer overflow in RSAZ modular exponentiation on x86_64 |
| 威胁等级来源 | nvd |
| 披露时间 | 2019-12-06 18:15:12 |
| 上次修改时间 | 2023-11-07 03:08:28 |

#### 2.1.17.3 漏洞描述
There is an overflow bug in the x64_64 Montgomery squaring procedure used in exponentiation with 512-bit moduli. No EC algorithms are affected. Analysis suggests that attacks against 2-prime RSA1024, 3-prime RSA1536, and DSA1024 as a result of this defect would be very difficult to perform and are not believed likely. Attacks against DH512 are considered just feasible. However, for an attack the target would have to re-use the DH512 private key, which is not recommended anyway. Also applications directly using the low level API BN_mod_exp may be affected if they use BN_FLG_CONSTTIME. Fixed in OpenSSL 1.1.1e (Affected 1.1.1-1.1.1d). Fixed in OpenSSL 1.0.2u (Affected 1.0.2-1.0.2t).

#### 2.1.17.4 相关链接
- https://avd.aquasec.com/nvd/cve-2019-1551
- https://secdb.alpinelinux.org/
- http://lists.opensuse.org/opensuse-security-announce/2020-01/msg00030.html
- http://packetstormsecurity.com/files/155754/Slackware-Security-Advisory-openssl-Updates.html
- https://access.redhat.com/security/cve/CVE-2019-1551
- https://git.openssl.org/gitweb/?p=openssl.git%3Ba=commitdiff%3Bh=419102400a2811582a7a3d4a4e317d72e5ce0a8f
- https://git.openssl.org/gitweb/?p=openssl.git%3Ba=commitdiff%3Bh=f1c5eea8a817075d31e43f5876993c6710238c98
- https://github.com/openssl/openssl/pull/10575
- https://linux.oracle.com/cve/CVE-2019-1551.html
- https://linux.oracle.com/errata/ELSA-2020-4514.html
- https://lists.debian.org/debian-lts-announce/2022/03/msg00023.html
- https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/DDHOAATPWJCXRNFMJ2SASDBBNU5RJONY/
- https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/EXDDAOWSAIEFQNBHWYE6PPYFV4QXGMCD/
- https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/XVEP3LAK4JSPRXFO4QF4GG2IVXADV3SO/
- https://nvd.nist.gov/vuln/detail/CVE-2019-1551
- https://seclists.org/bugtraq/2019/Dec/39
- https://seclists.org/bugtraq/2019/Dec/46
- https://security.gentoo.org/glsa/202004-10
- https://security.netapp.com/advisory/ntap-20191210-0001/
- https://ubuntu.com/security/notices/USN-4376-1
- https://ubuntu.com/security/notices/USN-4504-1
- https://usn.ubuntu.com/4376-1/
- https://usn.ubuntu.com/4504-1/
- https://www.cve.org/CVERecord?id=CVE-2019-1551
- https://www.debian.org/security/2019/dsa-4594
- https://www.debian.org/security/2021/dsa-4855
- https://www.openssl.org/news/secadv/20191206.txt
- https://www.oracle.com/security-alerts/cpuApr2021.html
- https://www.oracle.com/security-alerts/cpujan2021.html
- https://www.oracle.com/security-alerts/cpujul2020.html
- https://www.tenable.com/security/tns-2019-09
- https://www.tenable.com/security/tns-2020-03
- https://www.tenable.com/security/tns-2020-11
- https://www.tenable.com/security/tns-2021-10

### 2.1.18 CVE-2020-1971:openssl: EDIPARTYNAME NULL pointer de-reference
#### 2.1.18.1 软件包信息
| 软件包 URL | pkg:apk/alpine/libssl1.1@1.1.1d-r0?arch=x86_64&distro=3.10.3 |
|--- | --- |
| 软件包名称 | libssl1.1 |
| 安装版本 | 1.1.1d-r0 |
| 软件包 ID | libssl1.1@1.1.1d-r0 |
| 修复版本 | 1.1.1i-r0 |

#### 2.1.18.2 漏洞信息
| 漏洞编号 | CVE-2020-1971 |
|--- | --- |
| 威胁等级 | MEDIUM |
| 状态 | fixed |
| 漏洞标题 | openssl: EDIPARTYNAME NULL pointer de-reference |
| 威胁等级来源 | nvd |
| 披露时间 | 2020-12-08 16:15:11 |
| 上次修改时间 | 2024-06-21 19:15:16 |

#### 2.1.18.3 漏洞描述
The X.509 GeneralName type is a generic type for representing different types of names. One of those name types is known as EDIPartyName. OpenSSL provides a function GENERAL_NAME_cmp which compares different instances of a GENERAL_NAME to see if they are equal or not. This function behaves incorrectly when both GENERAL_NAMEs contain an EDIPARTYNAME. A NULL pointer dereference and a crash may occur leading to a possible denial of service attack. OpenSSL itself uses the GENERAL_NAME_cmp function for two purposes: 1) Comparing CRL distribution point names between an available CRL and a CRL distribution point embedded in an X509 certificate 2) When verifying that a timestamp response token signer matches the timestamp authority name (exposed via the API functions TS_RESP_verify_response and TS_RESP_verify_token) If an attacker can control both items being compared then that attacker could trigger a crash. For example if the attacker can trick a client or server into checking a malicious certificate against a malicious CRL then this may occur. Note that some applications automatically download CRLs based on a URL embedded in a certificate. This checking happens prior to the signatures on the certificate and CRL being verified. OpenSSL's s_server, s_client and verify tools have support for the "-crl_download" option which implements automatic CRL downloading and this attack has been demonstrated to work against those tools. Note that an unrelated bug means that affected versions of OpenSSL cannot parse or construct correct encodings of EDIPARTYNAME. However it is possible to construct a malformed EDIPARTYNAME that OpenSSL's parser will accept and hence trigger this attack. All OpenSSL 1.1.1 and 1.0.2 versions are affected by this issue. Other OpenSSL releases are out of support and have not been checked. Fixed in OpenSSL 1.1.1i (Affected 1.1.1-1.1.1h). Fixed in OpenSSL 1.0.2x (Affected 1.0.2-1.0.2w).

#### 2.1.18.4 相关链接
- https://avd.aquasec.com/nvd/cve-2020-1971
- https://secdb.alpinelinux.org/
- http://www.openwall.com/lists/oss-security/2021/09/14/2
- https://access.redhat.com/security/cve/CVE-2020-1971
- https://cert-portal.siemens.com/productcert/pdf/ssa-389290.pdf
- https://git.openssl.org/gitweb/?p=openssl.git%3Ba=commitdiff%3Bh=2154ab83e14ede338d2ede9bbe5cdfce5d5a6c9e
- https://git.openssl.org/gitweb/?p=openssl.git%3Ba=commitdiff%3Bh=f960d81215ebf3f65e03d4d5d857fb9b666d6920
- https://kb.pulsesecure.net/articles/Pulse_Security_Advisories/SA44676
- https://linux.oracle.com/cve/CVE-2020-1971.html
- https://linux.oracle.com/errata/ELSA-2021-9150.html
- https://lists.apache.org/thread.html/r63c6f2dd363d9b514d0a4bcf624580616a679898cc14c109a49b750c%40%3Cdev.tomcat.apache.org%3E
- https://lists.apache.org/thread.html/rbb769f771711fb274e0a4acb1b5911c8aab544a6ac5e8c12d40c5143%40%3Ccommits.pulsar.apache.org%3E
- https://lists.debian.org/debian-lts-announce/2020/12/msg00020.html
- https://lists.debian.org/debian-lts-announce/2020/12/msg00021.html
- https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/DGSI34Y5LQ5RYXN4M2I5ZQT65LFVDOUU/
- https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/PWPSSZNZOBJU2YR6Z4TGHXKYW3YP5QG7/
- https://nvd.nist.gov/vuln/detail/CVE-2020-1971
- https://security.FreeBSD.org/advisories/FreeBSD-SA-20:33.openssl.asc
- https://security.gentoo.org/glsa/202012-13
- https://security.netapp.com/advisory/ntap-20201218-0005/
- https://security.netapp.com/advisory/ntap-20210513-0002/
- https://security.netapp.com/advisory/ntap-20240621-0006/
- https://ubuntu.com/security/notices/USN-4662-1
- https://ubuntu.com/security/notices/USN-4745-1
- https://www.cve.org/CVERecord?id=CVE-2020-1971
- https://www.debian.org/security/2020/dsa-4807
- https://www.openssl.org/news/secadv/20201208.txt
- https://www.oracle.com//security-alerts/cpujul2021.html
- https://www.oracle.com/security-alerts/cpuApr2021.html
- https://www.oracle.com/security-alerts/cpuapr2022.html
- https://www.oracle.com/security-alerts/cpujan2021.html
- https://www.oracle.com/security-alerts/cpuoct2021.html
- https://www.tenable.com/security/tns-2020-11
- https://www.tenable.com/security/tns-2021-09
- https://www.tenable.com/security/tns-2021-10

### 2.1.19 CVE-2021-23841:openssl: NULL pointer dereference in X509_issuer_and_serial_hash()
#### 2.1.19.1 软件包信息
| 软件包 URL | pkg:apk/alpine/libssl1.1@1.1.1d-r0?arch=x86_64&distro=3.10.3 |
|--- | --- |
| 软件包名称 | libssl1.1 |
| 安装版本 | 1.1.1d-r0 |
| 软件包 ID | libssl1.1@1.1.1d-r0 |
| 修复版本 | 1.1.1j-r0 |

#### 2.1.19.2 漏洞信息
| 漏洞编号 | CVE-2021-23841 |
|--- | --- |
| 威胁等级 | MEDIUM |
| 状态 | fixed |
| 漏洞标题 | openssl: NULL pointer dereference in X509_issuer_and_serial_hash() |
| 威胁等级来源 | nvd |
| 披露时间 | 2021-02-16 17:15:13 |
| 上次修改时间 | 2024-06-21 19:15:17 |

#### 2.1.19.3 漏洞描述
The OpenSSL public API function X509_issuer_and_serial_hash() attempts to create a unique hash value based on the issuer and serial number data contained within an X509 certificate. However it fails to correctly handle any errors that may occur while parsing the issuer field (which might occur if the issuer field is maliciously constructed). This may subsequently result in a NULL pointer deref and a crash leading to a potential denial of service attack. The function X509_issuer_and_serial_hash() is never directly called by OpenSSL itself so applications are only vulnerable if they use this function directly and they use it on certificates that may have been obtained from untrusted sources. OpenSSL versions 1.1.1i and below are affected by this issue. Users of these versions should upgrade to OpenSSL 1.1.1j. OpenSSL versions 1.0.2x and below are affected by this issue. However OpenSSL 1.0.2 is out of support and no longer receiving public updates. Premium support customers of OpenSSL 1.0.2 should upgrade to 1.0.2y. Other users should upgrade to 1.1.1j. Fixed in OpenSSL 1.1.1j (Affected 1.1.1-1.1.1i). Fixed in OpenSSL 1.0.2y (Affected 1.0.2-1.0.2x).

#### 2.1.19.4 相关链接
- https://avd.aquasec.com/nvd/cve-2021-23841
- https://secdb.alpinelinux.org/
- http://seclists.org/fulldisclosure/2021/May/67
- http://seclists.org/fulldisclosure/2021/May/68
- http://seclists.org/fulldisclosure/2021/May/70
- https://access.redhat.com/security/cve/CVE-2021-23841
- https://cert-portal.siemens.com/productcert/pdf/ssa-637483.pdf
- https://git.openssl.org/gitweb/?p=openssl.git%3Ba=commitdiff%3Bh=122a19ab48091c657f7cb1fb3af9fc07bd557bbf
- https://git.openssl.org/gitweb/?p=openssl.git%3Ba=commitdiff%3Bh=8252ee4d90f3f2004d3d0aeeed003ad49c9a7807
- https://git.openssl.org/gitweb/?p=openssl.git;a=commitdiff;h=122a19ab48091c657f7cb1fb3af9fc07bd557bbf
- https://git.openssl.org/gitweb/?p=openssl.git;a=commitdiff;h=6a51b9e1d0cf0bf8515f7201b68fb0a3482b3dc1
- https://git.openssl.org/gitweb/?p=openssl.git;a=commitdiff;h=8252ee4d90f3f2004d3d0aeeed003ad49c9a7807
- https://git.openssl.org/gitweb/?p=openssl.git;a=commitdiff;h=9b1129239f3ebb1d1c98ce9ed41d5c9476c47cb2
- https://github.com/alexcrichton/openssl-src-rs
- https://kb.pulsesecure.net/articles/Pulse_Security_Advisories/SA44846
- https://linux.oracle.com/cve/CVE-2021-23841.html
- https://linux.oracle.com/errata/ELSA-2021-9561.html
- https://nvd.nist.gov/vuln/detail/CVE-2021-23841
- https://rustsec.org/advisories/RUSTSEC-2021-0058
- https://rustsec.org/advisories/RUSTSEC-2021-0058.html
- https://security.gentoo.org/glsa/202103-03
- https://security.netapp.com/advisory/ntap-20210219-0009
- https://security.netapp.com/advisory/ntap-20210219-0009/
- https://security.netapp.com/advisory/ntap-20210513-0002
- https://security.netapp.com/advisory/ntap-20210513-0002/
- https://security.netapp.com/advisory/ntap-20240621-0006/
- https://support.apple.com/kb/HT212528
- https://support.apple.com/kb/HT212529
- https://support.apple.com/kb/HT212534
- https://ubuntu.com/security/notices/USN-4738-1
- https://ubuntu.com/security/notices/USN-4745-1
- https://www.cve.org/CVERecord?id=CVE-2021-23841
- https://www.debian.org/security/2021/dsa-4855
- https://www.openssl.org/news/secadv/20210216.txt
- https://www.oracle.com//security-alerts/cpujul2021.html
- https://www.oracle.com/security-alerts/cpuApr2021.html
- https://www.oracle.com/security-alerts/cpuapr2022.html
- https://www.oracle.com/security-alerts/cpuoct2021.html
- https://www.tenable.com/security/tns-2021-03
- https://www.tenable.com/security/tns-2021-09

### 2.1.20 CVE-2021-3449:openssl: NULL pointer dereference in signature_algorithms processing
#### 2.1.20.1 软件包信息
| 软件包 URL | pkg:apk/alpine/libssl1.1@1.1.1d-r0?arch=x86_64&distro=3.10.3 |
|--- | --- |
| 软件包名称 | libssl1.1 |
| 安装版本 | 1.1.1d-r0 |
| 软件包 ID | libssl1.1@1.1.1d-r0 |
| 修复版本 | 1.1.1k-r0 |

#### 2.1.20.2 漏洞信息
| 漏洞编号 | CVE-2021-3449 |
|--- | --- |
| 威胁等级 | MEDIUM |
| 状态 | fixed |
| 漏洞标题 | openssl: NULL pointer dereference in signature_algorithms processing |
| 威胁等级来源 | nvd |
| 披露时间 | 2021-03-25 15:15:13 |
| 上次修改时间 | 2024-06-21 19:15:19 |

#### 2.1.20.3 漏洞描述
An OpenSSL TLS server may crash if sent a maliciously crafted renegotiation ClientHello message from a client. If a TLSv1.2 renegotiation ClientHello omits the signature_algorithms extension (where it was present in the initial ClientHello), but includes a signature_algorithms_cert extension then a NULL pointer dereference will result, leading to a crash and a denial of service attack. A server is only vulnerable if it has TLSv1.2 and renegotiation enabled (which is the default configuration). OpenSSL TLS clients are not impacted by this issue. All OpenSSL 1.1.1 versions are affected by this issue. Users of these versions should upgrade to OpenSSL 1.1.1k. OpenSSL 1.0.2 is not impacted by this issue. Fixed in OpenSSL 1.1.1k (Affected 1.1.1-1.1.1j).

#### 2.1.20.4 相关链接
- https://avd.aquasec.com/nvd/cve-2021-3449
- https://secdb.alpinelinux.org/
- http://www.openwall.com/lists/oss-security/2021/03/27/1
- http://www.openwall.com/lists/oss-security/2021/03/27/2
- http://www.openwall.com/lists/oss-security/2021/03/28/3
- http://www.openwall.com/lists/oss-security/2021/03/28/4
- https://access.redhat.com/security/cve/CVE-2021-3449
- https://cert-portal.siemens.com/productcert/pdf/ssa-389290.pdf
- https://cert-portal.siemens.com/productcert/pdf/ssa-772220.pdf
- https://git.openssl.org/gitweb/?p=openssl.git%3Ba=commitdiff%3Bh=fb9fa6b51defd48157eeb207f52181f735d96148
- https://git.openssl.org/gitweb/?p=openssl.git;a=commitdiff;h=fb9fa6b51defd48157eeb207f52181f735d96148
- https://github.com/alexcrichton/openssl-src-rs
- https://github.com/nodejs/node/pull/38083
- https://kb.pulsesecure.net/articles/Pulse_Security_Advisories/SA44845
- https://kc.mcafee.com/corporate/index?page=content&id=SB10356
- https://linux.oracle.com/cve/CVE-2021-3449.html
- https://linux.oracle.com/errata/ELSA-2021-9151.html
- https://lists.debian.org/debian-lts-announce/2021/08/msg00029.html
- https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/CCBFLLVQVILIVGZMBJL3IXZGKWQISYNP/
- https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/CCBFLLVQVILIVGZMBJL3IXZGKWQISYNP
- https://nvd.nist.gov/vuln/detail/CVE-2021-3449
- https://psirt.global.sonicwall.com/vuln-detail/SNWLID-2021-0013
- https://rustsec.org/advisories/RUSTSEC-2021-0055
- https://rustsec.org/advisories/RUSTSEC-2021-0055.html
- https://security.FreeBSD.org/advisories/FreeBSD-SA-21:07.openssl.asc
- https://security.gentoo.org/glsa/202103-03
- https://security.netapp.com/advisory/ntap-20210326-0006
- https://security.netapp.com/advisory/ntap-20210326-0006/
- https://security.netapp.com/advisory/ntap-20210513-0002
- https://security.netapp.com/advisory/ntap-20210513-0002/
- https://security.netapp.com/advisory/ntap-20240621-0006/
- https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-openssl-2021-GHY28dJd
- https://ubuntu.com/security/notices/USN-4891-1
- https://ubuntu.com/security/notices/USN-5038-1
- https://www.cve.org/CVERecord?id=CVE-2021-3449
- https://www.debian.org/security/2021/dsa-4875
- https://www.openssl.org/news/secadv/20210325.txt
- https://www.oracle.com//security-alerts/cpujul2021.html
- https://www.oracle.com/security-alerts/cpuApr2021.html
- https://www.oracle.com/security-alerts/cpuapr2022.html
- https://www.oracle.com/security-alerts/cpujul2022.html
- https://www.oracle.com/security-alerts/cpuoct2021.html
- https://www.tenable.com/security/tns-2021-05
- https://www.tenable.com/security/tns-2021-06
- https://www.tenable.com/security/tns-2021-09
- https://www.tenable.com/security/tns-2021-10

### 2.1.21 CVE-2021-23839:openssl: incorrect SSLv2 rollback protection
#### 2.1.21.1 软件包信息
| 软件包 URL | pkg:apk/alpine/libssl1.1@1.1.1d-r0?arch=x86_64&distro=3.10.3 |
|--- | --- |
| 软件包名称 | libssl1.1 |
| 安装版本 | 1.1.1d-r0 |
| 软件包 ID | libssl1.1@1.1.1d-r0 |
| 修复版本 | 1.1.1j-r0 |

#### 2.1.21.2 漏洞信息
| 漏洞编号 | CVE-2021-23839 |
|--- | --- |
| 威胁等级 | LOW |
| 状态 | fixed |
| 漏洞标题 | openssl: incorrect SSLv2 rollback protection |
| 威胁等级来源 | nvd |
| 披露时间 | 2021-02-16 17:15:13 |
| 上次修改时间 | 2024-06-21 19:15:16 |

#### 2.1.21.3 漏洞描述
OpenSSL 1.0.2 supports SSLv2. If a client attempts to negotiate SSLv2 with a server that is configured to support both SSLv2 and more recent SSL and TLS versions then a check is made for a version rollback attack when unpadding an RSA signature. Clients that support SSL or TLS versions greater than SSLv2 are supposed to use a special form of padding. A server that supports greater than SSLv2 is supposed to reject connection attempts from a client where this special form of padding is present, because this indicates that a version rollback has occurred (i.e. both client and server support greater than SSLv2, and yet this is the version that is being requested). The implementation of this padding check inverted the logic so that the connection attempt is accepted if the padding is present, and rejected if it is absent. This means that such as server will accept a connection if a version rollback attack has occurred. Further the server will erroneously reject a connection if a normal SSLv2 connection attempt is made. Only OpenSSL 1.0.2 servers from version 1.0.2s to 1.0.2x are affected by this issue. In order to be vulnerable a 1.0.2 server must: 1) have configured SSLv2 support at compile time (this is off by default), 2) have configured SSLv2 support at runtime (this is off by default), 3) have configured SSLv2 ciphersuites (these are not in the default ciphersuite list) OpenSSL 1.1.1 does not have SSLv2 support and therefore is not vulnerable to this issue. The underlying error is in the implementation of the RSA_padding_check_SSLv23() function. This also affects the RSA_SSLV23_PADDING padding mode used by various other functions. Although 1.1.1 does not support SSLv2 the RSA_padding_check_SSLv23() function still exists, as does the RSA_SSLV23_PADDING padding mode. Applications that directly call that function or use that padding mode will encounter this issue. However since there is no support for the SSLv2 protocol in 1.1.1 this is considered a bug and not a security issue in that version. OpenSSL 1.0.2 is out of support and no longer receiving public updates. Premium support customers of OpenSSL 1.0.2 should upgrade to 1.0.2y. Other users should upgrade to 1.1.1j. Fixed in OpenSSL 1.0.2y (Affected 1.0.2s-1.0.2x).

#### 2.1.21.4 相关链接
- https://avd.aquasec.com/nvd/cve-2021-23839
- https://secdb.alpinelinux.org/
- https://access.redhat.com/security/cve/CVE-2021-23839
- https://cert-portal.siemens.com/productcert/pdf/ssa-637483.pdf
- https://git.openssl.org/gitweb/?p=openssl.git%3Ba=commitdiff%3Bh=30919ab80a478f2d81f2e9acdcca3fa4740cd547
- https://kb.pulsesecure.net/articles/Pulse_Security_Advisories/SA44846
- https://nvd.nist.gov/vuln/detail/CVE-2021-23839
- https://security.netapp.com/advisory/ntap-20210219-0009/
- https://security.netapp.com/advisory/ntap-20240621-0006/
- https://www.cve.org/CVERecord?id=CVE-2021-23839
- https://www.openssl.org/news/secadv/20210216.txt
- https://www.oracle.com//security-alerts/cpujul2021.html
- https://www.oracle.com/security-alerts/cpuApr2021.html
- https://www.oracle.com/security-alerts/cpuapr2022.html
- https://www.oracle.com/security-alerts/cpuoct2021.html

### 2.1.22 CVE-2020-28928:In musl libc through 1.2.1, wcsnrtombs mishandles particular combinati ...
#### 2.1.22.1 软件包信息
| 软件包 URL | pkg:apk/alpine/musl@1.1.22-r3?arch=x86_64&distro=3.10.3 |
|--- | --- |
| 软件包名称 | musl |
| 安装版本 | 1.1.22-r3 |
| 软件包 ID | musl@1.1.22-r3 |
| 修复版本 | 1.1.22-r4 |

#### 2.1.22.2 漏洞信息
| 漏洞编号 | CVE-2020-28928 |
|--- | --- |
| 威胁等级 | MEDIUM |
| 状态 | fixed |
| 漏洞标题 | In musl libc through 1.2.1, wcsnrtombs mishandles particular combinati ... |
| 威胁等级来源 | nvd |
| 披露时间 | 2020-11-24 18:15:12 |
| 上次修改时间 | 2023-11-07 03:21:24 |

#### 2.1.22.3 漏洞描述
In musl libc through 1.2.1, wcsnrtombs mishandles particular combinations of destination buffer size and source character limit, as demonstrated by an invalid write access (buffer overflow).

#### 2.1.22.4 相关链接
- https://avd.aquasec.com/nvd/cve-2020-28928
- https://secdb.alpinelinux.org/
- http://www.openwall.com/lists/oss-security/2020/11/20/4
- https://lists.apache.org/thread.html/r2134abfe847bea7795f0e53756d10a47e6643f35ab8169df8b8a9eb1%40%3Cnotifications.apisix.apache.org%3E
- https://lists.apache.org/thread.html/r90b60cf49348e515257b4950900c1bd3ab95a960cf2469d919c7264e%40%3Cnotifications.apisix.apache.org%3E
- https://lists.apache.org/thread.html/ra63e8dc5137d952afc55dbbfa63be83304ecf842d1eab1ff3ebb29e2%40%3Cnotifications.apisix.apache.org%3E
- https://lists.debian.org/debian-lts-announce/2020/11/msg00050.html
- https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/LKQ3RVSMVZNZNO4D65W2CZZ4DMYFZN2Q/
- https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/UW27QVY7ERPTSGKS4KAWE5TU7EJWHKVQ/
- https://musl.libc.org/releases.html
- https://ubuntu.com/security/notices/USN-5990-1
- https://www.cve.org/CVERecord?id=CVE-2020-28928
- https://www.openwall.com/lists/oss-security/2020/11/20/4
- https://www.oracle.com//security-alerts/cpujul2021.html
- https://www.oracle.com/security-alerts/cpuoct2021.html

### 2.1.23 CVE-2020-28928:In musl libc through 1.2.1, wcsnrtombs mishandles particular combinati ...
#### 2.1.23.1 软件包信息
| 软件包 URL | pkg:apk/alpine/musl-utils@1.1.22-r3?arch=x86_64&distro=3.10.3 |
|--- | --- |
| 软件包名称 | musl-utils |
| 安装版本 | 1.1.22-r3 |
| 软件包 ID | musl-utils@1.1.22-r3 |
| 修复版本 | 1.1.22-r4 |

#### 2.1.23.2 漏洞信息
| 漏洞编号 | CVE-2020-28928 |
|--- | --- |
| 威胁等级 | MEDIUM |
| 状态 | fixed |
| 漏洞标题 | In musl libc through 1.2.1, wcsnrtombs mishandles particular combinati ... |
| 威胁等级来源 | nvd |
| 披露时间 | 2020-11-24 18:15:12 |
| 上次修改时间 | 2023-11-07 03:21:24 |

#### 2.1.23.3 漏洞描述
In musl libc through 1.2.1, wcsnrtombs mishandles particular combinations of destination buffer size and source character limit, as demonstrated by an invalid write access (buffer overflow).

#### 2.1.23.4 相关链接
- https://avd.aquasec.com/nvd/cve-2020-28928
- https://secdb.alpinelinux.org/
- http://www.openwall.com/lists/oss-security/2020/11/20/4
- https://lists.apache.org/thread.html/r2134abfe847bea7795f0e53756d10a47e6643f35ab8169df8b8a9eb1%40%3Cnotifications.apisix.apache.org%3E
- https://lists.apache.org/thread.html/r90b60cf49348e515257b4950900c1bd3ab95a960cf2469d919c7264e%40%3Cnotifications.apisix.apache.org%3E
- https://lists.apache.org/thread.html/ra63e8dc5137d952afc55dbbfa63be83304ecf842d1eab1ff3ebb29e2%40%3Cnotifications.apisix.apache.org%3E
- https://lists.debian.org/debian-lts-announce/2020/11/msg00050.html
- https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/LKQ3RVSMVZNZNO4D65W2CZZ4DMYFZN2Q/
- https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/UW27QVY7ERPTSGKS4KAWE5TU7EJWHKVQ/
- https://musl.libc.org/releases.html
- https://ubuntu.com/security/notices/USN-5990-1
- https://www.cve.org/CVERecord?id=CVE-2020-28928
- https://www.openwall.com/lists/oss-security/2020/11/20/4
- https://www.oracle.com//security-alerts/cpujul2021.html
- https://www.oracle.com/security-alerts/cpuoct2021.html

### 2.1.24 CVE-2019-19244:sqlite: allows a crash if a sub-select uses both DISTINCT and window functions and also has certain ORDER BY usage
#### 2.1.24.1 软件包信息
| 软件包 URL | pkg:apk/alpine/sqlite-libs@3.28.0-r1?arch=x86_64&distro=3.10.3 |
|--- | --- |
| 软件包名称 | sqlite-libs |
| 安装版本 | 3.28.0-r1 |
| 软件包 ID | sqlite-libs@3.28.0-r1 |
| 修复版本 | 3.28.0-r2 |

#### 2.1.24.2 漏洞信息
| 漏洞编号 | CVE-2019-19244 |
|--- | --- |
| 威胁等级 | HIGH |
| 状态 | fixed |
| 漏洞标题 | sqlite: allows a crash if a sub-select uses both DISTINCT and window functions and also has certain ORDER BY usage |
| 威胁等级来源 | nvd |
| 披露时间 | 2019-11-25 20:15:11 |
| 上次修改时间 | 2022-04-15 16:12:54 |

#### 2.1.24.3 漏洞描述
sqlite3Select in select.c in SQLite 3.30.1 allows a crash if a sub-select uses both DISTINCT and window functions, and also has certain ORDER BY usage.

#### 2.1.24.4 相关链接
- https://avd.aquasec.com/nvd/cve-2019-19244
- https://secdb.alpinelinux.org/
- https://access.redhat.com/security/cve/CVE-2019-19244
- https://cert-portal.siemens.com/productcert/pdf/ssa-389290.pdf
- https://github.com/sqlite/sqlite/commit/e59c562b3f6894f84c715772c4b116d7b5c01348
- https://nvd.nist.gov/vuln/detail/CVE-2019-19244
- https://ubuntu.com/security/notices/USN-4205-1
- https://usn.ubuntu.com/4205-1/
- https://www.cve.org/CVERecord?id=CVE-2019-19244
- https://www.oracle.com/security-alerts/cpuapr2020.html

### 2.1.25 CVE-2020-11655:sqlite: malformed window-function query leads to DoS
#### 2.1.25.1 软件包信息
| 软件包 URL | pkg:apk/alpine/sqlite-libs@3.28.0-r1?arch=x86_64&distro=3.10.3 |
|--- | --- |
| 软件包名称 | sqlite-libs |
| 安装版本 | 3.28.0-r1 |
| 软件包 ID | sqlite-libs@3.28.0-r1 |
| 修复版本 | 3.28.0-r3 |

#### 2.1.25.2 漏洞信息
| 漏洞编号 | CVE-2020-11655 |
|--- | --- |
| 威胁等级 | HIGH |
| 状态 | fixed |
| 漏洞标题 | sqlite: malformed window-function query leads to DoS |
| 威胁等级来源 | nvd |
| 披露时间 | 2020-04-09 03:15:11 |
| 上次修改时间 | 2022-04-08 10:34:22 |

#### 2.1.25.3 漏洞描述
SQLite through 3.31.1 allows attackers to cause a denial of service (segmentation fault) via a malformed window-function query because the AggInfo object's initialization is mishandled.

#### 2.1.25.4 相关链接
- https://avd.aquasec.com/nvd/cve-2020-11655
- https://secdb.alpinelinux.org/
- https://access.redhat.com/security/cve/CVE-2020-11655
- https://cert-portal.siemens.com/productcert/pdf/ssa-389290.pdf
- https://lists.debian.org/debian-lts-announce/2020/05/msg00006.html
- https://lists.debian.org/debian-lts-announce/2020/08/msg00037.html
- https://nvd.nist.gov/vuln/detail/CVE-2020-11655
- https://security.FreeBSD.org/advisories/FreeBSD-SA-20:22.sqlite.asc
- https://security.gentoo.org/glsa/202007-26
- https://security.netapp.com/advisory/ntap-20200416-0001/
- https://ubuntu.com/security/notices/USN-4394-1
- https://usn.ubuntu.com/4394-1/
- https://www.cve.org/CVERecord?id=CVE-2020-11655
- https://www.oracle.com/security-alerts/cpuApr2021.html
- https://www.oracle.com/security-alerts/cpujan2021.html
- https://www.oracle.com/security-alerts/cpujul2020.html
- https://www.oracle.com/security-alerts/cpuoct2020.html
- https://www.tenable.com/security/tns-2021-14
- https://www3.sqlite.org/cgi/src/info/4a302b42c7bf5e11
- https://www3.sqlite.org/cgi/src/tktview?name=af4556bb5c

### 2.1.26 CVE-2019-19242:sqlite: SQL injection in sqlite3ExprCodeTarget in expr.c
#### 2.1.26.1 软件包信息
| 软件包 URL | pkg:apk/alpine/sqlite-libs@3.28.0-r1?arch=x86_64&distro=3.10.3 |
|--- | --- |
| 软件包名称 | sqlite-libs |
| 安装版本 | 3.28.0-r1 |
| 软件包 ID | sqlite-libs@3.28.0-r1 |
| 修复版本 | 3.28.0-r2 |

#### 2.1.26.2 漏洞信息
| 漏洞编号 | CVE-2019-19242 |
|--- | --- |
| 威胁等级 | MEDIUM |
| 状态 | fixed |
| 漏洞标题 | sqlite: SQL injection in sqlite3ExprCodeTarget in expr.c |
| 威胁等级来源 | nvd |
| 披露时间 | 2019-11-27 17:15:14 |
| 上次修改时间 | 2022-04-19 15:36:45 |

#### 2.1.26.3 漏洞描述
SQLite 3.30.1 mishandles pExpr->y.pTab, as demonstrated by the TK_COLUMN case in sqlite3ExprCodeTarget in expr.c.

#### 2.1.26.4 相关链接
- https://avd.aquasec.com/nvd/cve-2019-19242
- https://secdb.alpinelinux.org/
- https://access.redhat.com/security/cve/CVE-2019-19242
- https://cert-portal.siemens.com/productcert/pdf/ssa-389290.pdf
- https://github.com/sqlite/sqlite/commit/57f7ece78410a8aae86aa4625fb7556897db384c
- https://nvd.nist.gov/vuln/detail/CVE-2019-19242
- https://ubuntu.com/security/notices/USN-4205-1
- https://usn.ubuntu.com/4205-1/
- https://www.cve.org/CVERecord?id=CVE-2019-19242
- https://www.oracle.com/security-alerts/cpuapr2020.html

### 2.1.27 CVE-2021-28831:busybox: invalid free or segmentation fault via malformed gzip data
#### 2.1.27.1 软件包信息
| 软件包 URL | pkg:apk/alpine/ssl_client@1.30.1-r3?arch=x86_64&distro=3.10.3 |
|--- | --- |
| 软件包名称 | ssl_client |
| 安装版本 | 1.30.1-r3 |
| 软件包 ID | ssl_client@1.30.1-r3 |
| 修复版本 | 1.30.1-r5 |

#### 2.1.27.2 漏洞信息
| 漏洞编号 | CVE-2021-28831 |
|--- | --- |
| 威胁等级 | HIGH |
| 状态 | fixed |
| 漏洞标题 | busybox: invalid free or segmentation fault via malformed gzip data |
| 威胁等级来源 | nvd |
| 披露时间 | 2021-03-19 05:15:13 |
| 上次修改时间 | 2023-11-07 03:32:23 |

#### 2.1.27.3 漏洞描述
decompress_gunzip.c in BusyBox through 1.32.1 mishandles the error bit on the huft_build result pointer, with a resultant invalid free or segmentation fault, via malformed gzip data.

#### 2.1.27.4 相关链接
- https://avd.aquasec.com/nvd/cve-2021-28831
- https://secdb.alpinelinux.org/
- https://access.redhat.com/security/cve/CVE-2021-28831
- https://git.busybox.net/busybox/commit/?id=f25d254dfd4243698c31a4f3153d4ac72aa9e9bd
- https://lists.debian.org/debian-lts-announce/2021/04/msg00001.html
- https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/3UDQGJRECXFS5EZVDH2OI45FMO436AC4/
- https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/Z7ZIFKPRR32ZYA3WAA2NXFA3QHHOU6FJ/
- https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/ZASBW7QRRLY5V2R44MQ4QQM4CZIDHM2U/
- https://nvd.nist.gov/vuln/detail/CVE-2021-28831
- https://security.gentoo.org/glsa/202105-09
- https://ubuntu.com/security/notices/USN-5179-1
- https://ubuntu.com/security/notices/USN-5179-2
- https://ubuntu.com/security/notices/USN-6335-1
- https://www.cve.org/CVERecord?id=CVE-2021-28831

### 2.1.28 CVE-2020-8037:tcpdump: ppp decapsulator can be convinced to allocate a large amount of memory
#### 2.1.28.1 软件包信息
| 软件包 URL | pkg:apk/alpine/tcpdump@4.9.3-r0?arch=x86_64&distro=3.10.3 |
|--- | --- |
| 软件包名称 | tcpdump |
| 安装版本 | 4.9.3-r0 |
| 软件包 ID | tcpdump@4.9.3-r0 |
| 修复版本 | 4.9.3-r1 |

#### 2.1.28.2 漏洞信息
| 漏洞编号 | CVE-2020-8037 |
|--- | --- |
| 威胁等级 | HIGH |
| 状态 | fixed |
| 漏洞标题 | tcpdump: ppp decapsulator can be convinced to allocate a large amount of memory |
| 威胁等级来源 | nvd |
| 披露时间 | 2020-11-04 18:15:20 |
| 上次修改时间 | 2023-11-07 03:26:15 |

#### 2.1.28.3 漏洞描述
The ppp decapsulator in tcpdump 4.9.3 can be convinced to allocate a large amount of memory.

#### 2.1.28.4 相关链接
- https://avd.aquasec.com/nvd/cve-2020-8037
- https://secdb.alpinelinux.org/
- http://seclists.org/fulldisclosure/2021/Apr/51
- https://access.redhat.com/security/cve/CVE-2020-8037
- https://github.com/the-tcpdump-group/tcpdump/commit/32027e199368dad9508965aae8cd8de5b6ab5231
- https://linux.oracle.com/cve/CVE-2020-8037.html
- https://linux.oracle.com/errata/ELSA-2021-4236.html
- https://lists.debian.org/debian-lts-announce/2020/11/msg00018.html
- https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/F2MX34MJIUJQGL6CMEPLTKFOOOC3CJ4Z/
- https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/LWDBONZVLC6BAOR2KM376DJCM4H3FERV/
- https://nvd.nist.gov/vuln/detail/CVE-2020-8037
- https://support.apple.com/kb/HT212325
- https://support.apple.com/kb/HT212326
- https://support.apple.com/kb/HT212327
- https://ubuntu.com/security/notices/USN-5331-1
- https://ubuntu.com/security/notices/USN-5331-2
- https://www.cve.org/CVERecord?id=CVE-2020-8037

## 2.2 Python
| 扫描目标 | Python |
|--- | --- |
| 软件包类型 | 应用层软件包 |
| 目标类型 | python-pkg |

### 2.2.1 CVE-2023-37920:python-certifi: Removal of e-Tugra root certificate
#### 2.2.1.1 软件包信息
| 软件包 URL | pkg:pypi/certifi@2019.11.28 |
|--- | --- |
| 软件包名称 | certifi |
| 安装版本 | 2019.11.28 |
| 修复版本 | 2023.7.22 |

#### 2.2.1.2 漏洞信息
| 漏洞编号 | CVE-2023-37920 |
|--- | --- |
| 威胁等级 | HIGH |
| 状态 | fixed |
| 漏洞标题 | python-certifi: Removal of e-Tugra root certificate |
| 威胁等级来源 | ghsa |
| 披露时间 | 2023-07-25 21:15:10 |
| 上次修改时间 | 2023-08-12 06:16:31 |

#### 2.2.1.3 漏洞描述
Certifi is a curated collection of Root Certificates for validating the trustworthiness of SSL certificates while verifying the identity of TLS hosts. Certifi prior to version 2023.07.22 recognizes "e-Tugra" root certificates. e-Tugra's root certificates were subject to an investigation prompted by reporting of security issues in their systems. Certifi 2023.07.22 removes root certificates from "e-Tugra" from the root store.

#### 2.2.1.4 相关链接
- https://avd.aquasec.com/nvd/cve-2023-37920
- https://github.com/advisories?query=type%3Areviewed+ecosystem%3Apip
- https://access.redhat.com/errata/RHSA-2023:7753
- https://access.redhat.com/security/cve/CVE-2023-37920
- https://bugzilla.redhat.com/2226586
- https://bugzilla.redhat.com/2242493
- https://errata.almalinux.org/9/ALSA-2023-7753.html
- https://github.com/certifi/python-certifi
- https://github.com/certifi/python-certifi/commit/8fb96ed81f71e7097ed11bc4d9b19afd7ea5c909
- https://github.com/certifi/python-certifi/security/advisories/GHSA-xqr8-7jwr-rhp7
- https://github.com/pypa/advisory-database/tree/main/vulns/certifi/PYSEC-2023-135.yaml
- https://groups.google.com/a/mozilla.org/g/dev-security-policy/c/C-HrP1SEq1A
- https://linux.oracle.com/cve/CVE-2023-37920.html
- https://linux.oracle.com/errata/ELSA-2024-0133.html
- https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/5EX6NG7WUFNUKGFHLM35KHHU3GAKXRTG
- https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/5EX6NG7WUFNUKGFHLM35KHHU3GAKXRTG/
- https://nvd.nist.gov/vuln/detail/CVE-2023-37920
- https://www.cve.org/CVERecord?id=CVE-2023-37920

### 2.2.2 CVE-2022-23491:python-certifi: untrusted root certificates
#### 2.2.2.1 软件包信息
| 软件包 URL | pkg:pypi/certifi@2019.11.28 |
|--- | --- |
| 软件包名称 | certifi |
| 安装版本 | 2019.11.28 |
| 修复版本 | 2022.12.07 |

#### 2.2.2.2 漏洞信息
| 漏洞编号 | CVE-2022-23491 |
|--- | --- |
| 威胁等级 | MEDIUM |
| 状态 | fixed |
| 漏洞标题 | python-certifi: untrusted root certificates |
| 威胁等级来源 | ghsa |
| 披露时间 | 2022-12-07 22:15:09 |
| 上次修改时间 | 2023-03-24 18:12:24 |

#### 2.2.2.3 漏洞描述
Certifi is a curated collection of Root Certificates for validating the trustworthiness of SSL certificates while verifying the identity of TLS hosts. Certifi 2022.12.07 removes root certificates from "TrustCor" from the root store. These are in the process of being removed from Mozilla's trust store. TrustCor's root certificates are being removed pursuant to an investigation prompted by media reporting that TrustCor's ownership also operated a business that produced spyware. Conclusions of Mozilla's investigation can be found in the linked google group discussion.

#### 2.2.2.4 相关链接
- https://avd.aquasec.com/nvd/cve-2022-23491
- https://github.com/advisories?query=type%3Areviewed+ecosystem%3Apip
- https://access.redhat.com/security/cve/CVE-2022-23491
- https://github.com/certifi/python-certifi
- https://github.com/certifi/python-certifi/commit/9e9e840925d7b8e76c76fdac1fab7e6e88c1c3b8
- https://github.com/certifi/python-certifi/security/advisories/GHSA-43fp-rhv2-5gv8
- https://github.com/pypa/advisory-database/tree/main/vulns/certifi/PYSEC-2022-42986.yaml
- https://groups.google.com/a/mozilla.org/g/dev-security-policy/c/oxX69KFvsm4/m/yLohoVqtCgAJ
- https://nvd.nist.gov/vuln/detail/CVE-2022-23491
- https://ubuntu.com/security/notices/USN-5761-1
- https://ubuntu.com/security/notices/USN-5761-2
- https://www.cve.org/CVERecord?id=CVE-2022-23491

### 2.2.3 CVE-2022-40899:python-future: remote attackers can cause denial of service via crafted Set-Cookie header from malicious web server
#### 2.2.3.1 软件包信息
| 软件包 URL | pkg:pypi/future@0.18.2 |
|--- | --- |
| 软件包名称 | future |
| 安装版本 | 0.18.2 |
| 修复版本 | 0.18.3 |

#### 2.2.3.2 漏洞信息
| 漏洞编号 | CVE-2022-40899 |
|--- | --- |
| 威胁等级 | HIGH |
| 状态 | fixed |
| 漏洞标题 | python-future: remote attackers can cause denial of service via crafted Set-Cookie header from malicious web server |
| 威胁等级来源 | ghsa |
| 披露时间 | 2022-12-23 00:15:14 |
| 上次修改时间 | 2023-01-23 18:57:18 |

#### 2.2.3.3 漏洞描述
An issue discovered in Python Charmers Future 0.18.2 and earlier allows remote attackers to cause a denial of service via crafted Set-Cookie header from malicious web server.

#### 2.2.3.4 相关链接
- https://avd.aquasec.com/nvd/cve-2022-40899
- https://github.com/advisories?query=type%3Areviewed+ecosystem%3Apip
- https://access.redhat.com/security/cve/CVE-2022-40899
- https://github.com/PythonCharmers/python-future
- https://github.com/PythonCharmers/python-future/blob/master/src/future/backports/http/cookiejar.py#L215
- https://github.com/PythonCharmers/python-future/commit/c91d70b34ef0402aef3e9d04364ba98509dca76f
- https://github.com/PythonCharmers/python-future/pull/610
- https://github.com/pypa/advisory-database/tree/main/vulns/future/PYSEC-2022-42991.yaml
- https://github.com/python/cpython/pull/17157
- https://nvd.nist.gov/vuln/detail/CVE-2022-40899
- https://pypi.org/project/future
- https://pypi.org/project/future/
- https://pyup.io/posts/pyup-discovers-redos-vulnerabilities-in-top-python-packages
- https://pyup.io/posts/pyup-discovers-redos-vulnerabilities-in-top-python-packages/
- https://ubuntu.com/security/notices/USN-5833-1
- https://www.cve.org/CVERecord?id=CVE-2022-40899

### 2.2.4 CVE-2024-3651:python-idna: potential DoS via resource consumption via specially crafted inputs to idna.encode()
#### 2.2.4.1 软件包信息
| 软件包 URL | pkg:pypi/idna@2.8 |
|--- | --- |
| 软件包名称 | idna |
| 安装版本 | 2.8 |
| 修复版本 | 3.7 |

#### 2.2.4.2 漏洞信息
| 漏洞编号 | CVE-2024-3651 |
|--- | --- |
| 威胁等级 | MEDIUM |
| 状态 | fixed |
| 漏洞标题 | python-idna: potential DoS via resource consumption via specially crafted inputs to idna.encode() |
| 威胁等级来源 | ghsa |
| 披露时间 | 2024-07-07 18:15:09 |
| 上次修改时间 | 2024-07-11 14:58:01 |

#### 2.2.4.3 漏洞描述
A vulnerability was identified in the kjd/idna library, specifically within the `idna.encode()` function, affecting version 3.6. The issue arises from the function's handling of crafted input strings, which can lead to quadratic complexity and consequently, a denial of service condition. This vulnerability is triggered by a crafted input that causes the `idna.encode()` function to process the input with considerable computational load, significantly increasing the processing time in a quadratic manner relative to the input size.

#### 2.2.4.4 相关链接
- https://avd.aquasec.com/nvd/cve-2024-3651
- https://github.com/advisories?query=type%3Areviewed+ecosystem%3Apip
- https://access.redhat.com/errata/RHSA-2024:3846
- https://access.redhat.com/security/cve/CVE-2024-3651
- https://bugzilla.redhat.com/2274779
- https://bugzilla.redhat.com/show_bug.cgi?id=2274779
- https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-3651
- https://errata.almalinux.org/9/ALSA-2024-3846.html
- https://errata.rockylinux.org/RLSA-2024:3846
- https://github.com/kjd/idna
- https://github.com/kjd/idna/commit/1d365e17e10d72d0b7876316fc7b9ca0eebdd38d
- https://github.com/kjd/idna/security/advisories/GHSA-jjg7-2v4v-x38h
- https://github.com/pypa/advisory-database/tree/main/vulns/idna/PYSEC-2024-60.yaml
- https://huntr.com/bounties/93d78d07-d791-4b39-a845-cbfabc44aadb
- https://linux.oracle.com/cve/CVE-2024-3651.html
- https://linux.oracle.com/errata/ELSA-2024-8365.html
- https://nvd.nist.gov/vuln/detail/CVE-2024-3651
- https://ubuntu.com/security/notices/USN-6780-1
- https://www.cve.org/CVERecord?id=CVE-2024-3651

### 2.2.5 CVE-2021-3572:python-pip: Incorrect handling of unicode separators in git references
#### 2.2.5.1 软件包信息
| 软件包 URL | pkg:pypi/pip@19.3.1 |
|--- | --- |
| 软件包名称 | pip |
| 安装版本 | 19.3.1 |
| 修复版本 | 21.1 |

#### 2.2.5.2 漏洞信息
| 漏洞编号 | CVE-2021-3572 |
|--- | --- |
| 威胁等级 | HIGH |
| 状态 | fixed |
| 漏洞标题 | python-pip: Incorrect handling of unicode separators in git references |
| 威胁等级来源 | ghsa |
| 披露时间 | 2021-11-10 18:15:09 |
| 上次修改时间 | 2024-06-21 19:15:20 |

#### 2.2.5.3 漏洞描述
A flaw was found in python-pip in the way it handled Unicode separators in git references. A remote attacker could possibly use this issue to install a different revision on a repository. The highest threat from this vulnerability is to data integrity. This is fixed in python-pip version 21.1.

#### 2.2.5.4 相关链接
- https://avd.aquasec.com/nvd/cve-2021-3572
- https://github.com/advisories?query=type%3Areviewed+ecosystem%3Apip
- https://access.redhat.com/errata/RHSA-2021:3254
- https://access.redhat.com/security/cve/CVE-2021-3572
- https://bugzilla.redhat.com/show_bug.cgi?id=1962856
- https://github.com/advisories/GHSA-5xp3-jfq3-5q8x
- https://github.com/pypa/advisory-database/tree/main/vulns/pip/PYSEC-2021-437.yaml
- https://github.com/pypa/pip
- https://github.com/pypa/pip/commit/e46bdda9711392fec0c45c1175bae6db847cb30b
- https://github.com/pypa/pip/issues/10042
- https://github.com/pypa/pip/issues/10042#issuecomment-857452480
- https://github.com/pypa/pip/pull/9827
- https://github.com/skazi0/CVE-2021-3572/blob/master/CVE-2021-3572-v9.0.1.patch
- https://linux.oracle.com/cve/CVE-2021-3572.html
- https://linux.oracle.com/errata/ELSA-2023-12349.html
- https://nvd.nist.gov/vuln/detail/CVE-2021-3572
- https://packetstormsecurity.com/files/162712/USN-4961-1.txt
- https://security.netapp.com/advisory/ntap-20240621-0006
- https://security.netapp.com/advisory/ntap-20240621-0006/
- https://ubuntu.com/security/notices/USN-4961-2
- https://www.cve.org/CVERecord?id=CVE-2021-3572
- https://www.oracle.com/security-alerts/cpuapr2022.html
- https://www.oracle.com/security-alerts/cpujul2022.html

### 2.2.6 CVE-2023-5752:pip: Mercurial configuration injectable in repo revision when installing via pip
#### 2.2.6.1 软件包信息
| 软件包 URL | pkg:pypi/pip@19.3.1 |
|--- | --- |
| 软件包名称 | pip |
| 安装版本 | 19.3.1 |
| 修复版本 | 23.3 |

#### 2.2.6.2 漏洞信息
| 漏洞编号 | CVE-2023-5752 |
|--- | --- |
| 威胁等级 | MEDIUM |
| 状态 | fixed |
| 漏洞标题 | pip: Mercurial configuration injectable in repo revision when installing via pip |
| 威胁等级来源 | ghsa |
| 披露时间 | 2023-10-25 18:17:44 |
| 上次修改时间 | 2024-06-10 18:15:24 |

#### 2.2.6.3 漏洞描述
When installing a package from a Mercurial VCS URL  (ie "pip install 

hg+...") with pip prior to v23.3, the specified Mercurial revision could

 be used to inject arbitrary configuration options to the "hg clone" 

call (ie "--config"). Controlling the Mercurial configuration can modify

 how and which repository is installed. This vulnerability does not 

affect users who aren't installing from Mercurial.



#### 2.2.6.4 相关链接
- https://avd.aquasec.com/nvd/cve-2023-5752
- https://github.com/advisories?query=type%3Areviewed+ecosystem%3Apip
- https://access.redhat.com/security/cve/CVE-2023-5752
- https://github.com/pypa/advisory-database/tree/main/vulns/pip/PYSEC-2023-228.yaml
- https://github.com/pypa/pip
- https://github.com/pypa/pip/commit/389cb799d0da9a840749fcd14878928467ed49b4
- https://github.com/pypa/pip/pull/12306
- https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/622OZXWG72ISQPLM5Y57YCVIMWHD4C3U
- https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/622OZXWG72ISQPLM5Y57YCVIMWHD4C3U/
- https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/65UKKF5LBHEFDCUSPBHUN4IHYX7SRMHH
- https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/65UKKF5LBHEFDCUSPBHUN4IHYX7SRMHH/
- https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/FXUVMJM25PUAZRQZBF54OFVKTY3MINPW
- https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/FXUVMJM25PUAZRQZBF54OFVKTY3MINPW/
- https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/KFC2SPFG5FLCZBYY2K3T5MFW2D22NG6E
- https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/KFC2SPFG5FLCZBYY2K3T5MFW2D22NG6E/
- https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/YBSB3SUPQ3VIFYUMHPO3MEQI4BJAXKCZ
- https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/YBSB3SUPQ3VIFYUMHPO3MEQI4BJAXKCZ/
- https://mail.python.org/archives/list/security-announce@python.org/thread/F4PL35U6X4VVHZ5ILJU3PWUWN7H7LZXL
- https://mail.python.org/archives/list/security-announce@python.org/thread/F4PL35U6X4VVHZ5ILJU3PWUWN7H7LZXL/
- https://nvd.nist.gov/vuln/detail/CVE-2023-5752
- https://www.cve.org/CVERecord?id=CVE-2023-5752

### 2.2.7 CVE-2023-32681:python-requests: Unintended leak of Proxy-Authorization header
#### 2.2.7.1 软件包信息
| 软件包 URL | pkg:pypi/requests@2.22.0 |
|--- | --- |
| 软件包名称 | requests |
| 安装版本 | 2.22.0 |
| 修复版本 | 2.31.0 |

#### 2.2.7.2 漏洞信息
| 漏洞编号 | CVE-2023-32681 |
|--- | --- |
| 威胁等级 | MEDIUM |
| 状态 | fixed |
| 漏洞标题 | python-requests: Unintended leak of Proxy-Authorization header |
| 威胁等级来源 | ghsa |
| 披露时间 | 2023-05-26 18:15:14 |
| 上次修改时间 | 2023-09-17 09:15:12 |

#### 2.2.7.3 漏洞描述
Requests is a HTTP library. Since Requests 2.3.0, Requests has been leaking Proxy-Authorization headers to destination servers when redirected to an HTTPS endpoint. This is a product of how we use `rebuild_proxies` to reattach the `Proxy-Authorization` header to requests. For HTTP connections sent through the tunnel, the proxy will identify the header in the request itself and remove it prior to forwarding to the destination server. However when sent over HTTPS, the `Proxy-Authorization` header must be sent in the CONNECT request as the proxy has no visibility into the tunneled request. This results in Requests forwarding proxy credentials to the destination server unintentionally, allowing a malicious actor to potentially exfiltrate sensitive information. This issue has been patched in version 2.31.0.





#### 2.2.7.4 相关链接
- https://avd.aquasec.com/nvd/cve-2023-32681
- https://github.com/advisories?query=type%3Areviewed+ecosystem%3Apip
- https://access.redhat.com/errata/RHSA-2023:4350
- https://access.redhat.com/security/cve/CVE-2023-32681
- https://bugzilla.redhat.com/2209469
- https://bugzilla.redhat.com/show_bug.cgi?id=2209469
- https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-32681
- https://errata.almalinux.org/9/ALSA-2023-4350.html
- https://errata.rockylinux.org/RLSA-2023:4520
- https://github.com/psf/requests
- https://github.com/psf/requests/commit/74ea7cf7a6a27a4eeb2ae24e162bcc942a6706d5
- https://github.com/psf/requests/releases/tag/v2.31.0
- https://github.com/psf/requests/security/advisories/GHSA-j8r2-6x86-q33q
- https://github.com/pypa/advisory-database/tree/main/vulns/requests/PYSEC-2023-74.yaml
- https://linux.oracle.com/cve/CVE-2023-32681.html
- https://linux.oracle.com/errata/ELSA-2023-7050.html
- https://lists.debian.org/debian-lts-announce/2023/06/msg00018.html
- https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/AW7HNFGYP44RT3DUDQXG2QT3OEV2PJ7Y
- https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/AW7HNFGYP44RT3DUDQXG2QT3OEV2PJ7Y/
- https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/KOYASTZDGQG2BWLSNBPL3TQRL2G7QYNZ
- https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/KOYASTZDGQG2BWLSNBPL3TQRL2G7QYNZ/
- https://nvd.nist.gov/vuln/detail/CVE-2023-32681
- https://security.gentoo.org/glsa/202309-08
- https://ubuntu.com/security/notices/USN-6155-1
- https://ubuntu.com/security/notices/USN-6155-2
- https://www.cve.org/CVERecord?id=CVE-2023-32681

### 2.2.8 CVE-2024-35195:requests: subsequent requests to the same host ignore cert verification
#### 2.2.8.1 软件包信息
| 软件包 URL | pkg:pypi/requests@2.22.0 |
|--- | --- |
| 软件包名称 | requests |
| 安装版本 | 2.22.0 |
| 修复版本 | 2.32.0 |

#### 2.2.8.2 漏洞信息
| 漏洞编号 | CVE-2024-35195 |
|--- | --- |
| 威胁等级 | MEDIUM |
| 状态 | fixed |
| 漏洞标题 | requests: subsequent requests to the same host ignore cert verification |
| 威胁等级来源 | ghsa |
| 披露时间 | 2024-05-20 21:15:09 |
| 上次修改时间 | 2024-06-10 17:16:29 |

#### 2.2.8.3 漏洞描述
Requests is a HTTP library. Prior to 2.32.0, when making requests through a Requests `Session`, if the first request is made with `verify=False` to disable cert verification, all subsequent requests to the same host will continue to ignore cert verification regardless of changes to the value of `verify`. This behavior will continue for the lifecycle of the connection in the connection pool. This vulnerability is fixed in 2.32.0.

#### 2.2.8.4 相关链接
- https://avd.aquasec.com/nvd/cve-2024-35195
- https://github.com/advisories?query=type%3Areviewed+ecosystem%3Apip
- https://access.redhat.com/security/cve/CVE-2024-35195
- https://github.com/psf/requests
- https://github.com/psf/requests/commit/a58d7f2ffb4d00b46dca2d70a3932a0b37e22fac
- https://github.com/psf/requests/pull/6655
- https://github.com/psf/requests/security/advisories/GHSA-9wx4-h78v-vm56
- https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/IYLSNK5TL46Q6XPRVMHVWS63MVJQOK4Q
- https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/IYLSNK5TL46Q6XPRVMHVWS63MVJQOK4Q/
- https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/N7WP6EYDSUOCOJYHDK5NX43PYZ4SNHGZ
- https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/N7WP6EYDSUOCOJYHDK5NX43PYZ4SNHGZ/
- https://nvd.nist.gov/vuln/detail/CVE-2024-35195
- https://www.cve.org/CVERecord?id=CVE-2024-35195

### 2.2.9 CVE-2022-40897:pypa-setuptools: Regular Expression Denial of Service (ReDoS) in package_index.py
#### 2.2.9.1 软件包信息
| 软件包 URL | pkg:pypi/setuptools@41.6.0 |
|--- | --- |
| 软件包名称 | setuptools |
| 安装版本 | 41.6.0 |
| 修复版本 | 65.5.1 |

#### 2.2.9.2 漏洞信息
| 漏洞编号 | CVE-2022-40897 |
|--- | --- |
| 威胁等级 | HIGH |
| 状态 | fixed |
| 漏洞标题 | pypa-setuptools: Regular Expression Denial of Service (ReDoS) in package_index.py |
| 威胁等级来源 | ghsa |
| 披露时间 | 2022-12-23 00:15:13 |
| 上次修改时间 | 2024-10-29 15:35:09 |

#### 2.2.9.3 漏洞描述
Python Packaging Authority (PyPA) setuptools before 65.5.1 allows remote attackers to cause a denial of service via HTML in a crafted package or custom PackageIndex page. There is a Regular Expression Denial of Service (ReDoS) in package_index.py.

#### 2.2.9.4 相关链接
- https://avd.aquasec.com/nvd/cve-2022-40897
- https://github.com/advisories?query=type%3Areviewed+ecosystem%3Apip
- https://access.redhat.com/errata/RHSA-2023:0952
- https://access.redhat.com/security/cve/CVE-2022-40897
- https://bugzilla.redhat.com/2158559
- https://bugzilla.redhat.com/show_bug.cgi?id=2158559
- https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-40897
- https://errata.almalinux.org/9/ALSA-2023-0952.html
- https://errata.rockylinux.org/RLSA-2023:0952
- https://github.com/pypa/advisory-database/tree/main/vulns/setuptools/PYSEC-2022-43012.yaml
- https://github.com/pypa/setuptools
- https://github.com/pypa/setuptools/blob/fe8a98e696241487ba6ac9f91faa38ade939ec5d/setuptools/package_index.py#L200
- https://github.com/pypa/setuptools/commit/43a9c9bfa6aa626ec2a22540bea28d2ca77964be
- https://github.com/pypa/setuptools/compare/v65.5.0...v65.5.1
- https://github.com/pypa/setuptools/issues/3659
- https://linux.oracle.com/cve/CVE-2022-40897.html
- https://linux.oracle.com/errata/ELSA-2024-2987.html
- https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/ADES3NLOE5QJKBLGNZNI2RGVOSQXA37R
- https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/ADES3NLOE5QJKBLGNZNI2RGVOSQXA37R/
- https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/YNA2BAH2ACBZ4TVJZKFLCR7L23BG5C3H
- https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/YNA2BAH2ACBZ4TVJZKFLCR7L23BG5C3H/
- https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/ADES3NLOE5QJKBLGNZNI2RGVOSQXA37R
- https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/YNA2BAH2ACBZ4TVJZKFLCR7L23BG5C3H
- https://nvd.nist.gov/vuln/detail/CVE-2022-40897
- https://pyup.io/posts/pyup-discovers-redos-vulnerabilities-in-top-python-packages
- https://pyup.io/posts/pyup-discovers-redos-vulnerabilities-in-top-python-packages/
- https://pyup.io/vulnerabilities/CVE-2022-40897/52495
- https://pyup.io/vulnerabilities/CVE-2022-40897/52495/
- https://security.netapp.com/advisory/ntap-20230214-0001
- https://security.netapp.com/advisory/ntap-20230214-0001/
- https://security.netapp.com/advisory/ntap-20240621-0006
- https://security.netapp.com/advisory/ntap-20240621-0006/
- https://setuptools.pypa.io/en/latest
- https://ubuntu.com/security/notices/USN-5817-1
- https://www.cve.org/CVERecord?id=CVE-2022-40897

### 2.2.10 CVE-2024-6345:pypa/setuptools: Remote code execution via download functions in the package_index module in pypa/setuptools
#### 2.2.10.1 软件包信息
| 软件包 URL | pkg:pypi/setuptools@41.6.0 |
|--- | --- |
| 软件包名称 | setuptools |
| 安装版本 | 41.6.0 |
| 修复版本 | 70.0.0 |

#### 2.2.10.2 漏洞信息
| 漏洞编号 | CVE-2024-6345 |
|--- | --- |
| 威胁等级 | HIGH |
| 状态 | fixed |
| 漏洞标题 | pypa/setuptools: Remote code execution via download functions in the package_index module in pypa/setuptools |
| 威胁等级来源 | ghsa |
| 披露时间 | 2024-07-15 01:15:01 |
| 上次修改时间 | 2024-07-15 13:00:34 |

#### 2.2.10.3 漏洞描述
A vulnerability in the package_index module of pypa/setuptools versions up to 69.1.1 allows for remote code execution via its download functions. These functions, which are used to download packages from URLs provided by users or retrieved from package index servers, are susceptible to code injection. If these functions are exposed to user-controlled inputs, such as package URLs, they can execute arbitrary commands on the system. The issue is fixed in version 70.0.

#### 2.2.10.4 相关链接
- https://avd.aquasec.com/nvd/cve-2024-6345
- https://github.com/advisories?query=type%3Areviewed+ecosystem%3Apip
- https://access.redhat.com/errata/RHSA-2024:6726
- https://access.redhat.com/security/cve/CVE-2024-6345
- https://bugzilla.redhat.com/2297771
- https://bugzilla.redhat.com/show_bug.cgi?id=2297771
- https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-6345
- https://errata.almalinux.org/9/ALSA-2024-6726.html
- https://errata.rockylinux.org/RLSA-2024:6726
- https://github.com/pypa/setuptools
- https://github.com/pypa/setuptools/commit/88807c7062788254f654ea8c03427adc859321f0
- https://github.com/pypa/setuptools/pull/4332
- https://huntr.com/bounties/d6362117-ad57-4e83-951f-b8141c6e7ca5
- https://linux.oracle.com/cve/CVE-2024-6345.html
- https://linux.oracle.com/errata/ELSA-2024-6726.html
- https://nvd.nist.gov/vuln/detail/CVE-2024-6345
- https://ubuntu.com/security/notices/USN-7002-1
- https://www.cve.org/CVERecord?id=CVE-2024-6345

### 2.2.11 CVE-2020-26137:python-urllib3: CRLF injection via HTTP request method
#### 2.2.11.1 软件包信息
| 软件包 URL | pkg:pypi/urllib3@1.24.3 |
|--- | --- |
| 软件包名称 | urllib3 |
| 安装版本 | 1.24.3 |
| 修复版本 | 1.25.9 |

#### 2.2.11.2 漏洞信息
| 漏洞编号 | CVE-2020-26137 |
|--- | --- |
| 威胁等级 | MEDIUM |
| 状态 | fixed |
| 漏洞标题 | python-urllib3: CRLF injection via HTTP request method |
| 威胁等级来源 | ghsa |
| 披露时间 | 2020-09-30 18:15:26 |
| 上次修改时间 | 2023-10-08 14:15:11 |

#### 2.2.11.3 漏洞描述
urllib3 before 1.25.9 allows CRLF injection if the attacker controls the HTTP request method, as demonstrated by inserting CR and LF control characters in the first argument of putrequest(). NOTE: this is similar to CVE-2020-26116.

#### 2.2.11.4 相关链接
- https://avd.aquasec.com/nvd/cve-2020-26137
- https://github.com/advisories?query=type%3Areviewed+ecosystem%3Apip
- https://access.redhat.com/security/cve/CVE-2020-26137
- https://bugs.python.org/issue39603
- https://bugzilla.redhat.com/show_bug.cgi?id=1883632
- https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-26137
- https://errata.almalinux.org/8/ALSA-2021-1761.html
- https://errata.rockylinux.org/RLSA-2021:1631
- https://github.com/urllib3/urllib3
- https://github.com/urllib3/urllib3/commit/1dd69c5c5982fae7c87a620d487c2ebf7a6b436b
- https://github.com/urllib3/urllib3/pull/1800
- https://linux.oracle.com/cve/CVE-2020-26137.html
- https://linux.oracle.com/errata/ELSA-2022-5235.html
- https://lists.debian.org/debian-lts-announce/2021/06/msg00015.html
- https://lists.debian.org/debian-lts-announce/2023/10/msg00012.html
- https://nvd.nist.gov/vuln/detail/CVE-2020-26137
- https://ubuntu.com/security/notices/USN-4570-1
- https://usn.ubuntu.com/4570-1
- https://usn.ubuntu.com/4570-1/
- https://www.cve.org/CVERecord?id=CVE-2020-26137
- https://www.oracle.com/security-alerts/cpujul2022.html
- https://www.oracle.com/security-alerts/cpuoct2021.html

### 2.2.12 CVE-2023-43804:python-urllib3: Cookie request header isn't stripped during cross-origin redirects
#### 2.2.12.1 软件包信息
| 软件包 URL | pkg:pypi/urllib3@1.24.3 |
|--- | --- |
| 软件包名称 | urllib3 |
| 安装版本 | 1.24.3 |
| 修复版本 | 2.0.6, 1.26.17 |

#### 2.2.12.2 漏洞信息
| 漏洞编号 | CVE-2023-43804 |
|--- | --- |
| 威胁等级 | MEDIUM |
| 状态 | fixed |
| 漏洞标题 | python-urllib3: Cookie request header isn't stripped during cross-origin redirects |
| 威胁等级来源 | ghsa |
| 披露时间 | 2023-10-04 17:15:10 |
| 上次修改时间 | 2024-02-01 00:55:23 |

#### 2.2.12.3 漏洞描述
urllib3 is a user-friendly HTTP client library for Python. urllib3 doesn't treat the `Cookie` HTTP header special or provide any helpers for managing cookies over HTTP, that is the responsibility of the user. However, it is possible for a user to specify a `Cookie` header and unknowingly leak information via HTTP redirects to a different origin if that user doesn't disable redirects explicitly. This issue has been patched in urllib3 version 1.26.17 or 2.0.5.

#### 2.2.12.4 相关链接
- https://avd.aquasec.com/nvd/cve-2023-43804
- https://github.com/advisories?query=type%3Areviewed+ecosystem%3Apip
- https://access.redhat.com/errata/RHSA-2024:2159
- https://access.redhat.com/security/cve/CVE-2023-43804
- https://bugzilla.redhat.com/2242493
- https://bugzilla.redhat.com/show_bug.cgi?id=2242493
- https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-43804
- https://errata.almalinux.org/9/ALSA-2024-2159.html
- https://errata.rockylinux.org/RLSA-2024:2986
- https://github.com/pypa/advisory-database/tree/main/vulns/urllib3/PYSEC-2023-192.yaml
- https://github.com/urllib3/urllib3
- https://github.com/urllib3/urllib3/commit/01220354d389cd05474713f8c982d05c9b17aafb
- https://github.com/urllib3/urllib3/commit/644124ecd0b6e417c527191f866daa05a5a2056d
- https://github.com/urllib3/urllib3/security/advisories/GHSA-v845-jxx5-vc9f
- https://linux.oracle.com/cve/CVE-2023-43804.html
- https://linux.oracle.com/errata/ELSA-2024-2987.html
- https://lists.debian.org/debian-lts-announce/2023/10/msg00012.html
- https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/5F5CUBAN5XMEBVBZPHFITBLMJV5FIJJ5
- https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/5F5CUBAN5XMEBVBZPHFITBLMJV5FIJJ5/
- https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/I3PR7C6RJ6JUBQKIJ644DMIJSUP36VDY
- https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/I3PR7C6RJ6JUBQKIJ644DMIJSUP36VDY/
- https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/NDAGZXYJ7H2G3SB47M453VQVNAWKAEJJ
- https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/NDAGZXYJ7H2G3SB47M453VQVNAWKAEJJ/
- https://nvd.nist.gov/vuln/detail/CVE-2023-43804
- https://ubuntu.com/security/notices/USN-6473-1
- https://ubuntu.com/security/notices/USN-6473-2
- https://www.cve.org/CVERecord?id=CVE-2023-43804

### 2.2.13 CVE-2023-45803:urllib3: Request body not stripped after redirect from 303 status changes request method to GET
#### 2.2.13.1 软件包信息
| 软件包 URL | pkg:pypi/urllib3@1.24.3 |
|--- | --- |
| 软件包名称 | urllib3 |
| 安装版本 | 1.24.3 |
| 修复版本 | 2.0.7, 1.26.18 |

#### 2.2.13.2 漏洞信息
| 漏洞编号 | CVE-2023-45803 |
|--- | --- |
| 威胁等级 | MEDIUM |
| 状态 | fixed |
| 漏洞标题 | urllib3: Request body not stripped after redirect from 303 status changes request method to GET |
| 威胁等级来源 | ghsa |
| 披露时间 | 2023-10-17 20:15:10 |
| 上次修改时间 | 2023-11-03 22:15:11 |

#### 2.2.13.3 漏洞描述
urllib3 is a user-friendly HTTP client library for Python. urllib3 previously wouldn't remove the HTTP request body when an HTTP redirect response using status 301, 302, or 303 after the request had its method changed from one that could accept a request body (like `POST`) to `GET` as is required by HTTP RFCs. Although this behavior is not specified in the section for redirects, it can be inferred by piecing together information from different sections and we have observed the behavior in other major HTTP client implementations like curl and web browsers. Because the vulnerability requires a previously trusted service to become compromised in order to have an impact on confidentiality we believe the exploitability of this vulnerability is low. Additionally, many users aren't putting sensitive data in HTTP request bodies, if this is the case then this vulnerability isn't exploitable. Both of the following conditions must be true to be affected by this vulnerability: 1. Using urllib3 and submitting sensitive information in the HTTP request body (such as form data or JSON) and 2. The origin service is compromised and starts redirecting using 301, 302, or 303 to a malicious peer or the redirected-to service becomes compromised. This issue has been addressed in versions 1.26.18 and 2.0.7 and users are advised to update to resolve this issue. Users unable to update should disable redirects for services that aren't expecting to respond with redirects with `redirects=False` and disable automatic redirects with `redirects=False` and handle 301, 302, and 303 redirects manually by stripping the HTTP request body.



#### 2.2.13.4 相关链接
- https://avd.aquasec.com/nvd/cve-2023-45803
- https://github.com/advisories?query=type%3Areviewed+ecosystem%3Apip
- https://access.redhat.com/errata/RHSA-2024:2132
- https://access.redhat.com/security/cve/CVE-2023-45803
- https://bugzilla.redhat.com/2246840
- https://bugzilla.redhat.com/2257028
- https://bugzilla.redhat.com/2257854
- https://bugzilla.redhat.com/show_bug.cgi?id=2246840
- https://bugzilla.redhat.com/show_bug.cgi?id=2257028
- https://bugzilla.redhat.com/show_bug.cgi?id=2257854
- https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-45803
- https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-52323
- https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-22195
- https://errata.almalinux.org/9/ALSA-2024-2132.html
- https://errata.rockylinux.org/RLSA-2024:2968
- https://github.com/pypa/advisory-database/tree/main/vulns/urllib3/PYSEC-2023-212.yaml
- https://github.com/urllib3/urllib3
- https://github.com/urllib3/urllib3/commit/4e50fbc5db74e32cabd5ccc1ab81fc103adfe0b3
- https://github.com/urllib3/urllib3/commit/4e98d57809dacab1cbe625fddeec1a290c478ea9
- https://github.com/urllib3/urllib3/commit/b594c5ceaca38e1ac215f916538fb128e3526a36
- https://github.com/urllib3/urllib3/releases/tag/1.26.18
- https://github.com/urllib3/urllib3/releases/tag/2.0.7
- https://github.com/urllib3/urllib3/security/advisories/GHSA-g4mx-q9vg-27p4
- https://linux.oracle.com/cve/CVE-2023-45803.html
- https://linux.oracle.com/errata/ELSA-2024-2988.html
- https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/4R2Y5XK3WALSR3FNAGN7JBYV2B343ZKB
- https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/4R2Y5XK3WALSR3FNAGN7JBYV2B343ZKB/
- https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/5F5CUBAN5XMEBVBZPHFITBLMJV5FIJJ5
- https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/5F5CUBAN5XMEBVBZPHFITBLMJV5FIJJ5/
- https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/PPDPLM6UUMN55ESPQWJFLLIZY4ZKCNRX
- https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/PPDPLM6UUMN55ESPQWJFLLIZY4ZKCNRX/
- https://nvd.nist.gov/vuln/detail/CVE-2023-45803
- https://ubuntu.com/security/notices/USN-6473-1
- https://ubuntu.com/security/notices/USN-6473-2
- https://www.cve.org/CVERecord?id=CVE-2023-45803
- https://www.rfc-editor.org/rfc/rfc9110.html#name-get

### 2.2.14 CVE-2024-37891:urllib3: proxy-authorization request header is not stripped during cross-origin redirects
#### 2.2.14.1 软件包信息
| 软件包 URL | pkg:pypi/urllib3@1.24.3 |
|--- | --- |
| 软件包名称 | urllib3 |
| 安装版本 | 1.24.3 |
| 修复版本 | 1.26.19, 2.2.2 |

#### 2.2.14.2 漏洞信息
| 漏洞编号 | CVE-2024-37891 |
|--- | --- |
| 威胁等级 | MEDIUM |
| 状态 | fixed |
| 漏洞标题 | urllib3: proxy-authorization request header is not stripped during cross-origin redirects |
| 威胁等级来源 | ghsa |
| 披露时间 | 2024-06-17 20:15:13 |
| 上次修改时间 | 2024-06-20 12:44:22 |

#### 2.2.14.3 漏洞描述
 urllib3 is a user-friendly HTTP client library for Python. When using urllib3's proxy support with `ProxyManager`, the `Proxy-Authorization` header is only sent to the configured proxy, as expected. However, when sending HTTP requests *without* using urllib3's proxy support, it's possible to accidentally configure the `Proxy-Authorization` header even though it won't have any effect as the request is not using a forwarding proxy or a tunneling proxy. In those cases, urllib3 doesn't treat the `Proxy-Authorization` HTTP header as one carrying authentication material and thus doesn't strip the header on cross-origin redirects. Because this is a highly unlikely scenario, we believe the severity of this vulnerability is low for almost all users. Out of an abundance of caution urllib3 will automatically strip the `Proxy-Authorization` header during cross-origin redirects to avoid the small chance that users are doing this on accident. Users should use urllib3's proxy support or disable automatic redirects to achieve safe processing of the `Proxy-Authorization` header, but we still decided to strip the header by default in order to further protect users who aren't using the correct approach. We believe the number of usages affected by this advisory is low. It requires all of the following to be true to be exploited: 1. Setting the `Proxy-Authorization` header without using urllib3's built-in proxy support. 2. Not disabling HTTP redirects. 3. Either not using an HTTPS origin server or for the proxy or target origin to redirect to a malicious origin. Users are advised to update to either version 1.26.19 or version 2.2.2. Users unable to upgrade may use the `Proxy-Authorization` header with urllib3's `ProxyManager`, disable HTTP redirects using `redirects=False` when sending requests, or not user the `Proxy-Authorization` header as mitigations.

#### 2.2.14.4 相关链接
- https://avd.aquasec.com/nvd/cve-2024-37891
- https://github.com/advisories?query=type%3Areviewed+ecosystem%3Apip
- https://access.redhat.com/errata/RHSA-2024:6162
- https://access.redhat.com/security/cve/CVE-2024-37891
- https://bugzilla.redhat.com/2292788
- https://bugzilla.redhat.com/show_bug.cgi?id=2292788
- https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-37891
- https://errata.almalinux.org/9/ALSA-2024-6162.html
- https://errata.rockylinux.org/RLSA-2024:8843
- https://github.com/urllib3/urllib3
- https://github.com/urllib3/urllib3/commit/40b6d1605814dd1db0a46e202d6e56f2e4c9a468
- https://github.com/urllib3/urllib3/commit/accff72ecc2f6cf5a76d9570198a93ac7c90270e
- https://github.com/urllib3/urllib3/security/advisories/GHSA-34jh-p97f-mpxf
- https://linux.oracle.com/cve/CVE-2024-37891.html
- https://linux.oracle.com/errata/ELSA-2024-8843.html
- https://nvd.nist.gov/vuln/detail/CVE-2024-37891
- https://ubuntu.com/security/notices/USN-7084-1
- https://ubuntu.com/security/notices/USN-7084-2
- https://www.cve.org/CVERecord?id=CVE-2024-37891

### 2.2.15 CVE-2022-40898:python-wheel: remote attackers can cause denial of service via attacker controlled input to wheel cli
#### 2.2.15.1 软件包信息
| 软件包 URL | pkg:pypi/wheel@0.33.6 |
|--- | --- |
| 软件包名称 | wheel |
| 安装版本 | 0.33.6 |
| 修复版本 | 0.38.1 |

#### 2.2.15.2 漏洞信息
| 漏洞编号 | CVE-2022-40898 |
|--- | --- |
| 威胁等级 | HIGH |
| 状态 | fixed |
| 漏洞标题 | python-wheel: remote attackers can cause denial of service via attacker controlled input to wheel cli |
| 威胁等级来源 | ghsa |
| 披露时间 | 2022-12-23 00:15:14 |
| 上次修改时间 | 2022-12-30 22:15:22 |

#### 2.2.15.3 漏洞描述
An issue discovered in Python Packaging Authority (PyPA) Wheel 0.37.1 and earlier allows remote attackers to cause a denial of service via attacker controlled input to wheel cli.

#### 2.2.15.4 相关链接
- https://avd.aquasec.com/nvd/cve-2022-40898
- https://github.com/advisories?query=type%3Areviewed+ecosystem%3Apip
- https://access.redhat.com/errata/RHSA-2023:6712
- https://access.redhat.com/security/cve/CVE-2022-40898
- https://bugzilla.redhat.com/2165864
- https://errata.almalinux.org/9/ALSA-2023-6712.html
- https://github.com/advisories/GHSA-qwmp-2cf2-g9g6
- https://github.com/pypa/wheel
- https://github.com/pypa/wheel/blob/main/src/wheel/wheelfile.py#L18
- https://github.com/pypa/wheel/commit/88f02bc335d5404991e532e7f3b0fc80437bf4e0
- https://linux.oracle.com/cve/CVE-2022-40898.html
- https://linux.oracle.com/errata/ELSA-2023-6712.html
- https://nvd.nist.gov/vuln/detail/CVE-2022-40898
- https://pypi.org/project/wheel
- https://pypi.org/project/wheel/
- https://pyup.io/posts/pyup-discovers-redos-vulnerabilities-in-top-python-packages
- https://pyup.io/posts/pyup-discovers-redos-vulnerabilities-in-top-python-packages/
- https://pyup.io/vulnerabilities/CVE-2022-40898/51499
- https://ubuntu.com/security/notices/USN-5821-1
- https://ubuntu.com/security/notices/USN-5821-2
- https://www.cve.org/CVERecord?id=CVE-2022-40898

