// Jenkinsfile - Pipeline de "Sistema Alumnos" (SecureDev · Evaluación Parcial 3 · OCY1102)
//
// VERSIÓN RESUELTA: Build -> Test -> SAST (Bandit) -> Dependencias (pip-audit)
//                   -> Deploy Staging -> DAST (OWASP ZAP) -> [gate] -> Deploy Producción
pipeline {
    agent any

    options {
        timestamps()
        timeout(time: 40, unit: 'MINUTES')
        disableConcurrentBuilds()
    }

    // Revisa GitHub cada ~3 minutos: cada push (tuyo o un PR de Dependabot fusionado) dispara un build.
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
                    // Versión = 1.0.<nº de build>+<commit corto>: une cada despliegue con su commit (trazabilidad)
                    def sha = sh(returnStdout: true, script: 'git rev-parse --short HEAD').trim()
                    env.APP_VERSION = "1.0.${env.BUILD_NUMBER}+${sha}"
                }
                echo "Versión de este build: ${env.APP_VERSION}"
                sh 'git log -1 --format="Commit %h de %an: %s"'
                // Cada build parte limpio: sin reportes viejos y con un entorno virtual nuevo
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

        // >>> [SEGURIDAD]: revisiones de seguridad continuas (SAST + dependencias)
        stage('Security Review (SAST)') {
            // Bandit está preinstalado en la imagen (/opt/herramientas/bin). Analiza el código estáticamente.
            steps {
                // No se hace fallar el build por hallazgos: se generan los reportes para documentar y trazar.
                sh 'bandit -r app.py -f json -o reports/bandit.json || true'
                sh 'bandit -r app.py -f txt  -o reports/bandit.txt  || true'
            }
            post {
                always { archiveArtifacts artifacts: 'reports/bandit.*', allowEmptyArchive: true }
            }
        }

        stage('Dependency Management') {
            // pip-audit (SCA) revisa requirements.txt contra la base de CVEs.
            steps {
                sh 'pip-audit -r requirements.txt -f json -o reports/pip-audit.json || true'
                sh 'pip-audit -r requirements.txt           -o reports/pip-audit.txt  || true'
            }
            post {
                always { archiveArtifacts artifacts: 'reports/pip-audit.*', allowEmptyArchive: true }
            }
        }

        // >>> [ZAP]: desplegar en staging y escanearlo con OWASP ZAP (DAST)
        stage('Deploy Staging') {
            steps {
                sh 'bash scripts/deploy.sh staging 5001'
            }
        }

        stage('DAST - OWASP ZAP') {
            steps {
                script {
                    // zap_scan.py termina con código 2 si hay alertas High/Medium -> marcamos UNSTABLE.
                    def rc = sh(returnStatus: true,
                                script: 'python3 scripts/zap_scan.py http://jenkins:5001')
                    if (rc == 2) {
                        currentBuild.result = 'UNSTABLE'
                        echo 'ZAP encontró alertas High/Medium: build UNSTABLE (revisa reports/zap-report.html).'
                    } else if (rc != 0) {
                        error("El escaneo ZAP falló con código ${rc}")
                    }
                }
            }
            post {
                always { archiveArtifacts artifacts: 'reports/zap-*', allowEmptyArchive: true }
            }
        }

        stage('Deploy Producción') {
            // >>> [GATE]: producción solo se despliega si el build sigue SANO (tests OK y ZAP sin High/Medium).
            when { expression { currentBuild.currentResult == 'SUCCESS' } }
            steps {
                sh 'bash scripts/deploy.sh produccion 5000'
                script { env.PRODUCCION = env.APP_VERSION }
            }
        }
    }

    post {
        always {
            // Registro de trazabilidad: build <-> versión <-> commit <-> pruebas <-> hallazgos <-> despliegue
            withEnv(["RESULTADO=${currentBuild.currentResult}"]) {
                sh 'python3 scripts/trazabilidad.py'
            }
            archiveArtifacts artifacts: 'reports/**', allowEmptyArchive: true
        }
    }
}
