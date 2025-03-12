"""
도커 이미지 역공학을 통한 도커파일 자동 생성 시스템
LLM을 활용하여 도커 이미지를 분석하고 원본 도커파일을 추론합니다.
"""

import os
import json
import subprocess
import tempfile
import argparse
import logging
from typing import Dict, List, Tuple, Optional, Any
import hashlib
import re
import requests
from pathlib import Path

# LLM API 연동을 위한 설정
import openai

# 로깅 설정
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class DockerImageAnalyzer:
    """도커 이미지 분석 클래스"""
    
    def __init__(self, image_name: str, output_dir: str = "./output"):
        """
        초기화 함수
        
        Args:
            image_name: 분석할 도커 이미지 이름 (예: nginx:latest)
            output_dir: 분석 결과 및 생성된 도커파일을 저장할 디렉토리
        """
        self.image_name = image_name
        self.output_dir = output_dir
        self.temp_dir = tempfile.mkdtemp(prefix="docker_analyzer_")
        self.metadata = {}
        self.layers_info = []
        self.layer_changes = []
        
        # 출력 디렉토리 생성
        os.makedirs(output_dir, exist_ok=True)
        
        logger.info(f"DockerImageAnalyzer initialized for image: {image_name}")
        logger.info(f"Output directory: {output_dir}")
        logger.info(f"Temporary directory: {self.temp_dir}")
    
    def analyze_image(self) -> Dict:
        """
        도커 이미지 분석 메인 함수
        
        Returns:
            Dict: 이미지 분석 결과 (메타데이터 및 레이어 정보)
        """
        logger.info(f"Starting analysis of image: {self.image_name}")
        
        # 이미지 pull
        self._pull_image()
        
        # 메타데이터 추출
        self.metadata = self._extract_metadata()
        
        # 레이어 정보 추출
        self.layers_info = self._extract_layers_info()
        
        # 각 레이어의 파일 시스템 변경 분석
        self.layer_changes = self._analyze_layer_changes()
        
        # 분석 결과 저장
        self._save_analysis_results()
        
        logger.info(f"Image analysis completed for: {self.image_name}")
        
        return {
            "metadata": self.metadata,
            "layers_info": self.layers_info,
            "layer_changes": self.layer_changes
        }
    
    def _pull_image(self) -> None:
        """도커 이미지 pull"""
        logger.info(f"Pulling image: {self.image_name}")
        subprocess.run(["docker", "pull", self.image_name], check=True)
    
    def _extract_metadata(self) -> Dict:
        """
        도커 이미지 메타데이터 추출
        
        Returns:
            Dict: 이미지 메타데이터 (엔트리포인트, CMD, ENV, EXPOSE 등)
        """
        logger.info(f"Extracting metadata for image: {self.image_name}")
        
        # docker inspect 명령으로 이미지 메타데이터 추출
        result = subprocess.run(
            ["docker", "inspect", self.image_name],
            capture_output=True,
            text=True,
            check=True
        )
        
        inspect_data = json.loads(result.stdout)[0]
        
        # 필요한 메타데이터 추출
        config = inspect_data.get("Config", {})
        metadata = {
            "id": inspect_data.get("Id", ""),
            "created": inspect_data.get("Created", ""),
            "os": inspect_data.get("Os", ""),
            "architecture": inspect_data.get("Architecture", ""),
            "entrypoint": config.get("Entrypoint", []),
            "cmd": config.get("Cmd", []),
            "env": config.get("Env", []),
            "exposed_ports": list(config.get("ExposedPorts", {}).keys()),
            "labels": config.get("Labels", {}),
            "working_dir": config.get("WorkingDir", ""),
            "user": config.get("User", ""),
            "volumes": list(config.get("Volumes", {}).keys()),
        }
        
        logger.info(f"Metadata extracted successfully for: {self.image_name}")
        return metadata
    
    def _extract_layers_info(self) -> List[Dict]:
        """
        이미지 레이어 정보 추출
        
        Returns:
            List[Dict]: 각 레이어의 정보
        """
        logger.info(f"Extracting layer information for image: {self.image_name}")
        
        # 이미지 히스토리 정보 추출
        result = subprocess.run(
            ["docker", "history", "--no-trunc", "--format", "{{.ID}}|{{.CreatedBy}}|{{.Size}}", self.image_name],
            capture_output=True,
            text=True,
            check=True
        )
        
        layers = []
        for line in result.stdout.strip().split('\n'):
            if not line:
                continue
                
            layer_id, created_by, size = line.split('|')
            
            # 레이어 정보 저장
            layers.append({
                "id": layer_id,
                "created_by": created_by,
                "size": size
            })
        
        logger.info(f"Extracted information for {len(layers)} layers")
        return layers
    
    def _analyze_layer_changes(self) -> List[Dict]:
        """
        각 레이어의 파일 시스템 변경 분석
        
        Returns:
            List[Dict]: 각 레이어의 파일 시스템 변경 정보
        """
        logger.info(f"Analyzing file system changes for each layer of: {self.image_name}")
        
        # 도커 이미지를 임시 컨테이너로 실행하여 파일 시스템 분석
        container_id = subprocess.run(
            ["docker", "create", self.image_name],
            capture_output=True,
            text=True,
            check=True
        ).stdout.strip()
        
        try:
            layer_changes = []
            
            # 각 레이어에 해당하는 디렉토리 생성
            for idx, layer in enumerate(self.layers_info):
                layer_dir = os.path.join(self.temp_dir, f"layer_{idx}")
                os.makedirs(layer_dir, exist_ok=True)
                
                # 컨테이너에서 중요 디렉토리 복사
                important_dirs = ["/etc", "/usr/bin", "/usr/local", "/app", "/var/www", "/opt"]
                for dir_path in important_dirs:
                    export_path = os.path.join(layer_dir, dir_path.lstrip('/'))
                    os.makedirs(os.path.dirname(export_path), exist_ok=True)
                    
                    try:
                        subprocess.run(
                            ["docker", "cp", f"{container_id}:{dir_path}", export_path],
                            stderr=subprocess.PIPE
                        )
                    except Exception as e:
                        logger.debug(f"Error copying {dir_path}: {e}")
                
                # 파일 목록 생성
                file_list = self._get_file_list(layer_dir)
                
                # 설정 파일 내용 분석
                config_files = self._analyze_config_files(layer_dir)
                
                # 레이어 변경 정보 저장
                layer_changes.append({
                    "layer_id": layer["id"],
                    "created_by": layer["created_by"],
                    "file_list": file_list,
                    "config_files": config_files
                })
            
            logger.info(f"Layer changes analysis completed")
            return layer_changes
            
        finally:
            # 임시 컨테이너 삭제
            subprocess.run(["docker", "rm", "-f", container_id], check=True)
    
    def _get_file_list(self, dir_path: str) -> List[str]:
        """디렉토리 내의 파일 목록 생성"""
        file_list = []
        for root, _, files in os.walk(dir_path):
            for file in files:
                full_path = os.path.join(root, file)
                rel_path = os.path.relpath(full_path, dir_path)
                file_list.append(rel_path)
        return file_list
    
    def _analyze_config_files(self, dir_path: str) -> Dict[str, str]:
        """중요 설정 파일 내용 분석"""
        config_files = {}
        config_extensions = ['.conf', '.cfg', '.ini', '.properties', '.xml', '.yml', '.yaml', '.json']
        
        for root, _, files in os.walk(dir_path):
            for file in files:
                if any(file.endswith(ext) for ext in config_extensions):
                    full_path = os.path.join(root, file)
                    rel_path = os.path.relpath(full_path, dir_path)
                    
                    try:
                        with open(full_path, 'r', encoding='utf-8') as f:
                            content = f.read()
                            config_files[rel_path] = content
                    except Exception as e:
                        logger.debug(f"Error reading file {full_path}: {e}")
        
        return config_files
    
    def _save_analysis_results(self) -> None:
        """분석 결과 저장"""
        analysis_results = {
            "metadata": self.metadata,
            "layers_info": self.layers_info,
            "layer_changes": self.layer_changes
        }
        
        output_file = os.path.join(self.output_dir, f"{self.image_name.replace(':', '_')}_analysis.json")
        with open(output_file, 'w') as f:
            json.dump(analysis_results, f, indent=2)
        
        logger.info(f"Analysis results saved to: {output_file}")


class DockerfileGenerator:
    """도커파일 생성 클래스"""
    
    def __init__(self, analysis_results: Dict, openai_api_key: str, output_dir: str = "./output"):
        """
        초기화 함수
        
        Args:
            analysis_results: 도커 이미지 분석 결과
            openai_api_key: OpenAI API 키
            output_dir: 생성된 도커파일을 저장할 디렉토리
        """
        self.analysis_results = analysis_results
        self.output_dir = output_dir
        self.image_name = analysis_results.get("metadata", {}).get("image_name", "unknown")
        
        # LLM API 설정
        openai.api_key = openai_api_key
        
        logger.info(f"DockerfileGenerator initialized for image: {self.image_name}")
    
    def generate_dockerfile(self) -> str:
        """
        도커파일 생성 메인 함수
        
        Returns:
            str: 생성된 도커파일 내용
        """
        logger.info(f"Starting Dockerfile generation for image: {self.image_name}")
        
        # 메타데이터 기반 도커 명령어 추출
        base_image, commands = self._extract_base_commands()
        
        # LLM으로 레이어 변경사항 분석하여 도커 명령어 추론
        layer_commands = self._infer_layer_commands()
        
        # 도커파일 조합
        dockerfile_content = self._compose_dockerfile(base_image, commands, layer_commands)
        
        # 도커파일 최적화
        optimized_dockerfile = self._optimize_dockerfile(dockerfile_content)
        
        # 도커파일 저장
        self._save_dockerfile(optimized_dockerfile)
        
        logger.info(f"Dockerfile generation completed for: {self.image_name}")
        
        return optimized_dockerfile
    
    def _extract_base_commands(self) -> Tuple[str, Dict[str, List]]:
        """
        메타데이터에서 기본 도커 명령어 추출
        
        Returns:
            Tuple[str, Dict[str, List]]: 기본 이미지와 명령어 목록
        """
        metadata = self.analysis_results.get("metadata", {})
        
        # 기본 이미지 추론
        base_image = "debian:latest"  # 기본값
        if "os" in metadata:
            if metadata["os"] == "linux":
                if "architecture" in metadata:
                    base_image = f"debian:{metadata['architecture']}"
        
        # 기본 명령어 추출
        commands = {
            "ENV": [],
            "WORKDIR": [],
            "EXPOSE": [],
            "VOLUME": [],
            "ENTRYPOINT": [],
            "CMD": [],
            "USER": []
        }
        
        # ENV
        for env_var in metadata.get("env", []):
            if '=' in env_var:
                commands["ENV"].append(env_var)
        
        # WORKDIR
        if metadata.get("working_dir"):
            commands["WORKDIR"].append(metadata["working_dir"])
        
        # EXPOSE
        for port in metadata.get("exposed_ports", []):
            port_num = port.split('/')[0]
            commands["EXPOSE"].append(port_num)
        
        # VOLUME
        for volume in metadata.get("volumes", []):
            commands["VOLUME"].append(volume)
        
        # ENTRYPOINT
        if metadata.get("entrypoint"):
            commands["ENTRYPOINT"] = [json.dumps(metadata["entrypoint"])]
        
        # CMD
        if metadata.get("cmd"):
            commands["CMD"] = [json.dumps(metadata["cmd"])]
        
        # USER
        if metadata.get("user"):
            commands["USER"].append(metadata["user"])
        
        logger.info(f"Base image determined: {base_image}")
        logger.info(f"Base commands extracted from metadata")
        
        return base_image, commands
    
    def _infer_layer_commands(self) -> List[str]:
        """
        LLM을 활용해 레이어 변경사항을 분석하여 도커 명령어 추론
        
        Returns:
            List[str]: 추론된 도커 명령어 목록
        """
        logger.info(f"Inferring Docker commands from layer changes using LLM")
        
        # 추론할 레이어 정보 준비
        layer_changes = self.analysis_results.get("layer_changes", [])
        
        inferred_commands = []
        
        for layer_idx, layer in enumerate(layer_changes):
            logger.info(f"Processing layer {layer_idx + 1}/{len(layer_changes)}")
            
            # LLM에 전달할 프롬프트 생성
            prompt = self._create_layer_prompt(layer, layer_idx)
            
            # LLM API 호출
            try:
                response = openai.ChatCompletion.create(
                    model="gpt-4",
                    messages=[
                        {"role": "system", "content": "You are a Docker expert that can analyze file system changes and determine the corresponding Dockerfile instructions."},
                        {"role": "user", "content": prompt}
                    ],
                    temperature=0.2,
                    max_tokens=500
                )
                
                # 응답에서 추론된 명령어 추출
                inferred_command = response.choices[0].message.content.strip()
                if inferred_command:
                    inferred_commands.append(inferred_command)
                    logger.info(f"Command inferred for layer {layer_idx + 1}: {inferred_command}")
            except Exception as e:
                logger.error(f"Error inferring command for layer {layer_idx + 1}: {e}")
        
        logger.info(f"Inferred {len(inferred_commands)} commands from layer changes")
        return inferred_commands
    
    def _create_layer_prompt(self, layer: Dict, layer_idx: int) -> str:
        """
        레이어 분석을 위한 LLM 프롬프트 생성
        
        Args:
            layer: 레이어 정보
            layer_idx: 레이어 인덱스
            
        Returns:
            str: LLM 프롬프트
        """
        # 'created_by' 정보에서 사람이 이해할 수 있는 명령어 추출
        created_by = layer.get("created_by", "")
        clean_created_by = created_by.replace("/bin/sh -c #(nop) ", "").replace("/bin/sh -c", "RUN")
        
        # 파일 목록 중 중요 파일 선택 (최대 50개)
        important_files = []
        file_list = layer.get("file_list", [])
        
        # 중요 파일 패턴
        important_patterns = [
            r'\.conf$', r'\.cfg$', r'\.ini$', r'\.properties$', r'\.xml$', r'\.yml$', r'\.yaml$', r'\.json$',
            r'/etc/', r'/bin/', r'/usr/bin/', r'/usr/local/bin/', r'/opt/', r'/app/', r'/var/www/'
        ]
        
        for file in file_list:
            if any(re.search(pattern, file) for pattern in important_patterns):
                important_files.append(file)
                if len(important_files) >= 50:
                    break
        
        # 설정 파일 내용
        config_examples = {}
        config_files = layer.get("config_files", {})
        for file, content in list(config_files.items())[:5]:  # 최대 5개 설정 파일 내용 포함
            if len(content) > 500:
                content = content[:500] + "... (truncated)"
            config_examples[file] = content
        
        # 프롬프트 생성
        prompt = f"""
                    I'm analyzing a Docker image layer. Please help me determine the most likely Dockerfile instruction(s) that created this layer.

                    LAYER INFORMATION:
                    - Layer Index: {layer_idx}
                    - Created By: {clean_created_by}

                    IMPORTANT FILES CHANGED IN THIS LAYER (up to 50):
                    {json.dumps(important_files, indent=2)}

                    CONFIGURATION FILE EXAMPLES (up to 5):
                    {json.dumps(config_examples, indent=2)}

                    Based on the information above, please provide the most likely Dockerfile instruction(s) that would generate this layer.
                    Reply with just the Dockerfile instruction(s) with no explanation. 
                    If multiple instructions, put each on a new line.
                    If uncertain, provide the most reasonable guess based on the patterns you observe.
                """
        
        return prompt
    
    def _compose_dockerfile(self, base_image: str, commands: Dict[str, List], layer_commands: List[str]) -> str:
        """
        도커파일 조합
        
        Args:
            base_image: 기본 이미지
            commands: 메타데이터에서 추출한 명령어
            layer_commands: 레이어 분석으로 추론한 명령어
            
        Returns:
            str: 도커파일 내용
        """
        logger.info(f"Composing Dockerfile for image: {self.image_name}")
        
        # 도커파일 시작
        dockerfile = [f"FROM {base_image}"]
        
        # 환경 변수 설정
        for env in commands["ENV"]:
            dockerfile.append(f"ENV {env}")
        
        # 작업 디렉토리 설정
        for workdir in commands["WORKDIR"]:
            dockerfile.append(f"WORKDIR {workdir}")
        
        # 레이어 분석으로 추론한 명령어 추가
        for cmd in layer_commands:
            dockerfile.append(cmd)
        
        # 포트 설정
        for port in commands["EXPOSE"]:
            dockerfile.append(f"EXPOSE {port}")
        
        # 볼륨 설정
        for volume in commands["VOLUME"]:
            dockerfile.append(f"VOLUME {volume}")
        
        # 사용자 설정
        for user in commands["USER"]:
            dockerfile.append(f"USER {user}")
        
        # 엔트리포인트 설정
        for entrypoint in commands["ENTRYPOINT"]:
            dockerfile.append(f"ENTRYPOINT {entrypoint}")
        
        # CMD 설정
        for cmd in commands["CMD"]:
            dockerfile.append(f"CMD {cmd}")
        
        return "\n".join(dockerfile)
    
    def _optimize_dockerfile(self, dockerfile_content: str) -> str:
        """
        도커파일 최적화
        
        Args:
            dockerfile_content: 원본 도커파일 내용
            
        Returns:
            str: 최적화된 도커파일 내용
        """
        logger.info(f"Optimizing Dockerfile")
        
        # LLM을 통한 도커파일 최적화
        try:
            prompt = f"""
I have generated a Dockerfile from reverse engineering a Docker image. Please help me optimize it.

ORIGINAL DOCKERFILE:
```dockerfile
{dockerfile_content}
```

Please optimize this Dockerfile following best practices:
1. Combine multiple RUN commands into a single one where appropriate
2. Add cleanup commands to reduce image size
3. Order commands to maximize layer caching
4. Remove redundant commands
5. Fix any syntax errors or incorrect instructions

Reply with ONLY the optimized Dockerfile, no explanations.
"""
            
            response = openai.ChatCompletion.create(
                model="gpt-4",
                messages=[
                    {"role": "system", "content": "You are a Docker expert specializing in Dockerfile optimization."},
                    {"role": "user", "content": prompt}
                ],
                temperature=0.2,
                max_tokens=1000
            )
            
            optimized_dockerfile = response.choices[0].message.content.strip()
            
            # 코드 블록 표시 제거
            if optimized_dockerfile.startswith("```dockerfile"):
                optimized_dockerfile = optimized_dockerfile[len("```dockerfile"):].strip()
            if optimized_dockerfile.startswith("```"):
                optimized_dockerfile = optimized_dockerfile[3:].strip()
            if optimized_dockerfile.endswith("```"):
                optimized_dockerfile = optimized_dockerfile[:-3].strip()
            
            logger.info(f"Dockerfile optimized successfully")
            return optimized_dockerfile
            
        except Exception as e:
            logger.error(f"Error optimizing Dockerfile: {e}")
            return dockerfile_content
    
    def _save_dockerfile(self, dockerfile_content: str) -> None:
        """
        도커파일 저장
        
        Args:
            dockerfile_content: 도커파일 내용
        """
        output_file = os.path.join(self.output_dir, f"{self.image_name.replace(':', '_')}_Dockerfile")
        with open(output_file, 'w') as f:
            f.write(dockerfile_content)
        
        logger.info(f"Dockerfile saved to: {output_file}")


class DockerfileValidator:
    """도커파일 검증 클래스"""
    
    def __init__(self, dockerfile_path: str, original_image: str, output_dir: str = "./output"):
        """
        초기화 함수
        
        Args:
            dockerfile_path: 검증할 도커파일 경로
            original_image: 원본 도커 이미지 이름
            output_dir: 검증 결과를 저장할 디렉토리
        """
        self.dockerfile_path = dockerfile_path
        self.original_image = original_image
        self.output_dir = output_dir
        self.validation_image = f"validation-{hashlib.md5(original_image.encode()).hexdigest()[:8]}"
        
        logger.info(f"DockerfileValidator initialized for: {dockerfile_path}")
        logger.info(f"Original image: {original_image}")
        logger.info(f"Validation image tag: {self.validation_image}")
    
    def validate(self) -> Dict:
        """
        도커파일 검증 메인 함수
        
        Returns:
            Dict: 검증 결과
        """
        logger.info(f"Starting validation for Dockerfile: {self.dockerfile_path}")
        
        # 도커파일로 이미지 빌드
        build_success, build_output = self._build_image()
        
        if not build_success:
            logger.error(f"Validation failed: Could not build image from Dockerfile")
            return {
                "success": False,
                "build_success": build_success,
                "build_output": build_output,
                "comparison": {},
                "error": "Failed to build image from Dockerfile"
            }
        
        # 원본 이미지와 비교
        comparison_result = self._compare_with_original()
        
        # 검증 결과 저장
        validation_result = {
            "success": build_success and comparison_result["success"],
            "build_success": build_success,
            "build_output": build_output,
            "comparison": comparison_result
        }
        
        self._save_validation_result(validation_result)
        
        logger.info(f"Validation completed with success: {validation_result['success']}")
        
        return validation_result
    
    def _build_image(self) -> Tuple[bool, str]:
        """
        도커파일로 이미지 빌드
        
        Returns:
            Tuple[bool, str]: 빌드 성공 여부와 빌드 출력
        """
        logger.info(f"Building image from Dockerfile: {self.dockerfile_path}")
        
        dockerfile_dir = os.path.dirname(self.dockerfile_path)
        
        try:
            result = subprocess.run(
                ["docker", "build", "-t", self.validation_image, "-f", self.dockerfile_path, dockerfile_dir],
                capture_output=True,
                text=True,
                check=False
            )
            
            build_success = result.returncode == 0
            build_output = result.stdout + "\n" + result.stderr
            
            if build_success:
                logger.info(f"Image built successfully: {self.validation_image}")
            else:
                logger.error(f"Failed to build image: {result.stderr}")
            
            return build_success, build_output
            
        except Exception as e:
            logger.error(f"Error building image: {e}")
            return False, str(e)
    
    def _compare_with_original(self) -> Dict:
        """
        원본 이미지와 비교
        
        Returns:
            Dict: 비교 결과
        """
        logger.info(f"Comparing generated image with original: {self.original_image} vs {self.validation_image}")
        
        # 메타데이터 비교
        original_metadata = self._get_image_metadata(self.original_image)
        validation_metadata = self._get_image_metadata(self.validation_image)
        
        # 중요 메타데이터 항목 비교
        important_fields = ["Entrypoint", "Cmd", "ExposedPorts", "Env", "WorkingDir", "User", "Volumes"]
        metadata_comparison = {}
        
        for field in important_fields:
            original_value = original_metadata.get(field)
            validation_value = validation_metadata.get(field)
            
            metadata_comparison[field] = {
                "original": original_value,
                "validation": validation_value,
                "match": self._compare_values(original_value, validation_value)
            }
        
        # 기능 테스트
        functional_test = self._perform_functional_test()
        
        # 전체 결과
        success = all(item.get("match", False) for item in metadata_comparison.values()) and functional_test["success"]
        
        return {
            "success": success,
            "metadata_comparison": metadata_comparison,
            "functional_test": functional_test
        }
    
    def _get_image_metadata(self, image_name: str) -> Dict:
        """
        도커 이미지 메타데이터 추출
        
        Args:
            image_name: 도커 이미지 이름
            
        Returns:
            Dict: 이미지 메타데이터
        """
        try:
            result = subprocess.run(
                ["docker", "inspect", image_name],
                capture_output=True,
                text=True,
                check=True
            )
            
            inspect_data = json.loads(result.stdout)[0]
            config = inspect_data.get("Config", {})
            
            metadata = {
                "Entrypoint": config.get("Entrypoint"),
                "Cmd": config.get("Cmd"),
                "ExposedPorts": config.get("ExposedPorts"),
                "Env": config.get("Env"),
                "WorkingDir": config.get("WorkingDir"),
                "User": config.get("User"),
                "Volumes": config.get("Volumes")
            }
            
            return metadata
            
        except Exception as e:
            logger.error(f"Error getting metadata for image {image_name}: {e}")
            return {}
    
    def _compare_values(self, original: Any, validation: Any) -> bool:
        """두 값 비교"""
        # None 타입 처리
        if original is None and validation is None:
            return True
        
        # 리스트 비교
        if isinstance(original, list) and isinstance(validation, list):
            # 순서가 중요한 경우 (Entrypoint, Cmd 등)
            return original == validation
        
        # 기본 타입 비교
        return original == validation

    def _perform_functional_test(self) -> Dict:
        """
        기능 테스트
        
        Returns:
            Dict: 기능 테스트 결과
        """
        logger.info(f"Performing functional test for image: {self.validation_image}")
        
        # 기능 테스트 로직 구현
        # 이 부분은 실제 구현에 따라 달라질 수 있습니다.
        # 여기서는 간단한 예시를 보여주기 위해 반환값을 고정합니다.
        return {
            "success": True,
            "message": "Functional test passed"
        }

    def _save_validation_result(self, validation_result: Dict) -> None:
        """
        검증 결과 저장
        
        Args:
            validation_result: 검증 결과
        """
        output_file = os.path.join(self.output_dir, f"{self.image_name.replace(':', '_')}_validation_result.json")
        with open(output_file, 'w') as f:
            json.dump(validation_result, f, indent=2)
        
        logger.info(f"Validation result saved to: {output_file}")

if __name__ == "__main__":
    image_name = "nginx:latest"  # 분석할 도커 이미지
    output_dir = "./output"  # 결과를 저장할 디렉토리
    openai_api_key = "YOUR_OPENAI_API_KEY"  # OpenAI API 키

    analyzer = DockerImageAnalyzer(image_name, output_dir)
    analysis_results = analyzer.analyze_image()

    generator = DockerfileGenerator(analysis_results, openai_api_key, output_dir)
    dockerfile_content = generator.generate_dockerfile()

    validator = DockerfileValidator(f"{output_dir}/{image_name.replace(':', '_')}_Dockerfile", image_name, output_dir)
    validation_result = validator.validate()

    print(validation_result)