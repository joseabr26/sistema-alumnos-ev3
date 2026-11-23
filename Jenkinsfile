// Jenkinsfile LIVIANO (sin OWASP ZAP) - "Sistema Alumnos" (SecureDev · EV3 · OCY1102)
//
// Versión para equipos con poca RAM: Build -> Test -> SAST (Bandit) -> SCA (pip-audit) -> Deploy Producción.
// La etapa DAST (OWASP ZAP) y el Deploy Staging se OMITEN aquí porque ZAP (Java) necesita mucha memoria.
// Esa etapa (Evidencias 5 y 6) se ejecuta en un PC del laboratorio con más RAM, usando el Jenkinsfile completo.
pipeline {
    agent any

    options {
        timestamps()
        timeout(time: 30, unit: 'MINUTES')
        disableConcurrentBuilds()
    }

    triggers {
        pollSCM('H/3 * * * *')
    }

    environment {
        PIP_DISABLE_PIP_VERSION_CHECK = '1'
    }

    stages {
        stage('Build') {
            steps {
                script {
                    def sha = sh(returnStdout: true, script: 'git rev-parse --short HEAD').trim()
                    env.APP_VERSION = "1.0.${env.BUILD_NUMBER}+${sha}"
                }
                echo "Versión de este build: ${env.APP_VERSION}"
                sh 'git log -1 --format="Commit %h de %an: %s"'
                sh 'rm -rf .venv reports && mkdir -p reports'
                sh 'python3 -m venv .venv'
                sh '.venv/bin/pip install --quiet -r requirements.txt -r requirements-dev.txt'
                sh '.venv/bin/python -m compileall -q app.py'
            }
        }

        stage('Test') {
            steps {
                sh '.venv/bin/python -m pytest --junitxml=reports/junit.xml'
            }
            post {
                always {
                    junit allowEmptyResults: true, testResults: 'reports/junit.xml'
                }
            }
        }

        stage('Security Review (SAST)') {
            steps {
                sh 'bandit -r app.py -f json -o reports/bandit.json || true'
                sh 'bandit -r app.py -f txt  -o reports/bandit.txt  || true'
            }
            post {
                always { archiveArtifacts artifacts: 'reports/bandit.*', allowEmptyArchive: true }
            }
        }

        stage('Dependency Management') {
            steps {
                sh 'pip-audit -r requirements.txt -f json -o reports/pip-audit.json || true'
                sh 'pip-audit -r requirements.txt           -o reports/pip-audit.txt  || true'
            }
            post {
                always { archiveArtifacts artifacts: 'reports/pip-audit.*', allowEmptyArchive: true }
            }
        }

        stage('Deploy Producción') {
            when { expression { currentBuild.currentResult == 'SUCCESS' } }
            steps {
                sh 'bash scripts/deploy.sh produccion 5000'
                script { env.PRODUCCION = env.APP_VERSION }
            }
        }
    }

    post {
        always {
            withEnv(["RESULTADO=${currentBuild.currentResult}"]) {
                sh 'python3 scripts/trazabilidad.py'
            }
            archiveArtifacts artifacts: 'reports/**', allowEmptyArchive: true
        }
    }
}
