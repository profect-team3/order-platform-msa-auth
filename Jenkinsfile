pipeline {
  agent {
    kubernetes {
      inheritFrom 'docker-builder'
      defaultContainer 'docker'
    }
  }

  environment {
    // ---- ECR/이미지 ----
    ECR_REPO    = "order-auth"
    SERVICE_KEY = "auth"
    FINAL_TAG   = "${env.BUILD_NUMBER}"
    ECR_REG     = "${env.AWS_ACCOUNT}.dkr.ecr.${env.AWS_REGION}.amazonaws.com"
    LOCAL_IMAGE = "${ECR_REPO}:${FINAL_TAG}"
    REMOTE_TAG  = "${ECR_REG}/${ECR_REPO}:${FINAL_TAG}"

    // GitOps 관련 환경 변수 (전역으로 지정)
    GITOPS_JOB    = "gitops-update"
    GITOPS_PATH   = "env/msa-apps/values.yaml"
    GITOPS_BRANCH = "main"

    // 컨테이너 간 공유 경로(aws→docker)
    ECR_PW_FILE = '/home/jenkins/agent/.ecr_pw'
  }

  options {
    timeout(time: 30, unit: 'MINUTES')
    disableConcurrentBuilds()
  }

  stages {
    stage('Wait dockerd') {
      steps {
        container('docker') {
          sh '''
            set -euo pipefail
            export DOCKER_HOST=${DOCKER_HOST:-tcp://127.0.0.1:2375}
            echo "[INFO] waiting dockerd on $DOCKER_HOST ..."
            for i in $(seq 1 120); do
              if docker version >/dev/null 2>&1; then
                docker info | sed -n '1,20p'
                exit 0
              fi
              sleep 1
            done
            echo "[ERROR] dockerd not ready after 120s"
            exit 1
          '''
        }
      }
    }

    stage('Checkout') {
      steps { checkout scm }
    }

    stage('Login to ECR') {
      steps {
        container('aws') {
          sh '''
            set -euo pipefail
            aws ecr get-login-password --region "${AWS_REGION}" > "${ECR_PW_FILE}"
            chmod 600 "${ECR_PW_FILE}"
          '''
        }
        container('docker') {
          sh '''
            set -euo pipefail
            export DOCKER_HOST=${DOCKER_HOST:-tcp://localhost:2375}
            cat "${ECR_PW_FILE}" | docker login --username AWS --password-stdin "${ECR_REG}"
          '''
        }
      }
    }

    stage('Docker Build') {
      steps {
        container('docker') {
          sh '''
            set -euo pipefail
            export DOCKER_HOST=${DOCKER_HOST:-tcp://localhost:2375}
            echo "[INFO] Building ${LOCAL_IMAGE}"
            docker build --pull -t "${LOCAL_IMAGE}" .
            docker tag "${LOCAL_IMAGE}" "${REMOTE_TAG}"
          '''
        }
      }
    }

    stage('Docker Push') {
      steps {
        container('docker') {
          sh '''
            set -euo pipefail
            export DOCKER_HOST=${DOCKER_HOST:-tcp://localhost:2375}
            echo "[INFO] Pushing ${REMOTE_TAG}"
            docker push "${REMOTE_TAG}"
          '''
        }
      }
    }

    stage('Get Image Digest (info)') {
      steps {
        container('aws') {
          script {
            env.IMAGE_DIGEST_SHA = sh(
              returnStdout: true,
              script: '''
                aws ecr describe-images \
                  --repository-name "${ECR_REPO}" \
                  --image-ids imageTag="${FINAL_TAG}" \
                  --region "${AWS_REGION}" \
                  --query 'imageDetails[0].imageDigest' --output text
              '''
            ).trim()
            env.IMAGE_DIGEST = "${env.ECR_REG}/${env.ECR_REPO}@${env.IMAGE_DIGEST_SHA}"
            echo "[INFO] IMAGE_DIGEST_SHA=${env.IMAGE_DIGEST_SHA}"
            echo "[INFO] IMAGE_DIGEST=${env.IMAGE_DIGEST}"
          }
        }
      }
    }

    stage('Trigger GitOps Update Pipeline') {
      steps {
        container('aws') {
          script {
            build job: env.GITOPS_JOB, wait: true, parameters: [
              string(name: 'SERVICE_KEY',   value: env.SERVICE_KEY),
              string(name: 'IMAGE_DIGEST',  value: env.IMAGE_DIGEST),
              string(name: 'GITOPS_PATH',   value: env.GITOPS_PATH),
              string(name: 'GITOPS_BRANCH', value: env.GITOPS_BRANCH),
              booleanParam(name: 'USE_PR',  value: true)
            ]
          }
        }
      }
    }

    stage('Cleanup') {
      steps {
        container('docker') {
          sh '''
            set +e
            export DOCKER_HOST=${DOCKER_HOST:-tcp://localhost:2375}
            docker logout "${ECR_REG}" || true
            docker image prune -f || true
            rm -f "${ECR_PW_FILE}" || true
          '''
        }
      }
    }
  }

  post {
    always {
      echo '[POST] build finished'
    }
  }
}