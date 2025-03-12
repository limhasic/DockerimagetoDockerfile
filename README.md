# DockerimagetoDockerfile
LLM 기반의 도커 이미지 역공학을 통해 도커 파일을 생성하는 시스템

A system that generates Docker files by reverse engineering Docker images based on LLM.

참조해야할 사이트

**DockerImage 역공학**

- dfimage: 
도커 이미지의 메타데이터를 이용하여 원본 도커파일을 근사적으로 재구성하는 오픈소스 파이썬 스크립트

- Dedockify:
이미지 내부 구조를 분석하여 도커파일을 역공학하는 또 다른 오픈소스 프로젝

**LLM 기반의 Dockerfile 생성 Agent**

- Repo2Run :
https://github.com/bytedance/Repo2Run
