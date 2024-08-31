pipeline {
    agent any
    // agent {
    //     label 'alpinejdk17'
    // }
     environment {
    //     SONARQUBE_URL = 'http://192.168.0.101:9000'
    //     SONARQUBE_AUTH_TOKEN = credentials('sonar-cred') // Replace with your credential ID
    //     REGISTRY_AUTH_USERNAME = 'aspodkatilov@gmail.com'
    //     REGISTRY_AUTH_PASSWORD = 'P@ssw0rd!'
    //     HARBOR_URL = 'https://hub.docker.com'
    //     DOCKER_IMAGE_NAME="podkatilovas/pygoat:${env.BUILD_NUMBER}"
         DOCKER_IMAGE_NAME="podkatilovas/nettu-meet:latest"
    //     SSH_PASSWORD='kali'
         SEMGREP_REPORT = 'semgrep-report.json'
         DEPTRACK_PRJ_NAME="podkatilovas_exam"
         DEPTRACK_URL="https://s410-exam.cyber-ed.space:8081"
         DEPTRACK_TOKEN="odt_SfCq7Csub3peq7Y6lSlQy5Ngp9sSYpJl"
    //     SCA_REPORT='sca_report.txt'
    //     SEMGREP_REPORT_MAX_ERROR="200"
     }

     stages {
        // stage("CheckJenkins") {
        //     steps {
        //         sh 'echo "I am working"'
        //     }
        // }

        // stage('SASTSemGrep') {
        //     agent {
        //         label 'alpine'
        //     }

        //     steps {
        //         script {
        //             try {
        //                 sh '''
        //                     apk update && apk add --no-cache python3 py3-pip py3-virtualenv
        //                     python3 -m venv venv
        //                     . venv/bin/activate
        //                     pip install semgrep
        //                     semgrep ci --config auto --json > ${SEMGREP_REPORT}
        //                 '''
        //             } catch (Exception e) {
        //                 echo 'Semgrep encountered issues.'
        //             }
        //         }

        //         sh 'ls -lth'
        //         stash name: 'semgrep-report', includes: "${SEMGREP_REPORT}"
        //         archiveArtifacts artifacts: "${SEMGREP_REPORT}", allowEmptyArchive: true
        //     }
        // }   

        // stage('Zap') {
        //     agent {
        //         label 'alpine'
        //     }    

        //     steps {
        //         sh 'curl -L -o ZAP_2.15.0_Linux.tar.gz https://github.com/zaproxy/zaproxy/releases/download/v2.15.0/ZAP_2.15.0_Linux.tar.gz'
        //         sh 'tar -xzf ZAP_2.15.0_Linux.tar.gz'
        //         sh './ZAP_2.15.0/zap.sh -cmd -addonupdate -addoninstall wappalyzer -addoninstall pscanrulesBeta'
        //         sh 'ls -lt'            
        //         sh './ZAP_2.15.0/zap.sh -cmd -quickurl https://s410-exam.cyber-ed.space:8084 -quickout $(pwd)/zapsh-report.json'
        //         sh 'ls -lt'
        //         sh 'cat ./zapsh-report.json'
        //         stash name: 'zapsh-report', includes: 'zapsh-report.json'
        //         archiveArtifacts artifacts: 'zapsh-report.json', allowEmptyArchive: true         
        //     }            
        // }      

        stage('SCA') {
            agent {
                label 'dind'
            }
            when {
                expression { true }
            }

            steps {
                sh '''
                    echo ${WORKSPACE}
                    pwd
                    response=$(curl -k -s -X PUT "${DEPTRACK_URL}/api/v1/project" \
                        -H "X-Api-Key: ${DEPTRACK_TOKEN}" \
                        -H "Content-Type: application/json" \
                        -d '{
                            "name": "podkatilovas_exam_2",
                            "version": "1.0.0"
                        }')
                    uuid=$(echo $response | jq -r '.uuid')
                    echo "Project UUID: $uuid"

                    cd server
                    docker build . -t ${DOCKER_IMAGE_NAME} -f Dockerfile
                    docker image ls
                    sudo apt-get install -y curl

                    curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh
                    ./bin/trivy image --format json --output ${WORKSPACE}/sbom.json ${DOCKER_IMAGE_NAME}

                    cd ${WORKSPACE}
                    # sbomresponse = $(curl -k -X POST "${DEPTRACK_URL}/api/v1/project/${uuid}/sbom" \
                    #     -H "X-Api-Key: ${DEPTRACK_TOKEN}" \
                    #     -H "Content-Type: application/json" \
                    #     -F "file=@sbom.json")

                     #http_code=${response: -3}

                     #echo "Result = $http_code"

                     #if [ "$http_code" -ne 200 ]; then
                     #    echo "Error: Failed to upload SBOM"
                     #    exit 1
                     #fi
                    #ls -lt                    
                '''
                stash name: 'sbom', includes: 'sbom.json'
                archiveArtifacts artifacts: "${WORKSPACE}/sbom.json", allowEmptyArchive: true
            }
        }     

    //    stage('SonarTools') {
    //         steps {
    //             script {
    //                 // Install necessary tools with sudo
    //                 sh '''
    //                 apt-get update
    //                 apt-get install -y curl unzip
    //                 # Install SonarQube Scanner
    //                 curl -sSLo sonar-scanner.zip https://binaries.sonarsource.com/Distribution/sonar-scanner-cli/sonar-scanner-cli-6.1.0.4477-linux-x64.zip
    //                 unzip sonar-scanner.zip -d /opt/
    //                 ln -s /opt/sonar-scanner-6.1.0.4477-linux-x64/bin/sonar-scanner /usr/local/bin/sonar-scanner
    //                 '''
    //             }
    //         }
    //     }    
        // stage('SonarQube') {
        //     steps {
        //         script {
        //             withSonarQubeEnv('sonar') {
        //                 sh 'echo ${SONARQUBE_AUTH_TOKEN}'
        //                 sh 'sonar-scanner -Dsonar.login=${SONARQUBE_AUTH_TOKEN}'
        //             }
        //         }
        //     }
        // }
        // stage('SonarQubeTool') {
        //      when {
        //         expression { false }
        //     }
        //     steps {
        //         script {
        //             def scannerHome = tool 'sonar';
        //             withSonarQubeEnv('sonar') {
        //                 sh 'printenv | grep SONAR'
        //                 sh 'echo ${scannerHome}'
        //                 sh "${scannerHome}/bin/sonar-scanner"
        //                 sh "ls -lt"
        //                 sh 'pwd'
        //             }
        //         }

        //         archiveArtifacts artifacts: 'sonar-report.json', allowEmptyArchive: true
        //     }
        // }

        //  stage('QualityGate') {
        //      when {
        //         expression { false }
        //     }
        //     steps {
        //         script {
        //             def qg = waitForQualityGate()
                    
        //             echo "Quality Gate status: ${qg.status}"                                        
        //         }
        //     }
        // }
        //  stage('BuildDockerImage') {
        //      when {
        //         expression { false }
        //     }
        //     agent {
        //         label 'dnd'
        //     }
        //     steps {
        //         script {
        //             //sh 'echo "${HARBOR_URL} harbor.cyber-ed.labs" | sudo tee -a /etc/hosts'                    
        //             //sh 'echo ${REGISTRY_AUTH_PASSWORD} | docker login ${HARBOR_URL} --username ${REGISTRY_AUTH_USERNAME} --password-stdin'
        //             sh 'echo ${REGISTRY_AUTH_PASSWORD} | docker login --username ${REGISTRY_AUTH_USERNAME} --password-stdin'
        //             sh 'docker build -f Dockerfile -t ${DOCKER_IMAGE_NAME} .'                    
        //             sh 'docker push ${DOCKER_IMAGE_NAME}'
        //         }
        //     }
        // }

        // stage('Deploy') {
        //      when {
        //         expression { false }
        //     }
        //     steps {
        //         sh 'apt update && apt install sshpass'
        //         sh """
        //             sshpass -p 'kali' ssh -o StrictHostKeyChecking=no -p 2222 kali@192.168.0.101 <<EOF
        //             echo ${SSH_PASSWORD} | sudo -S docker login -u ${REGISTRY_AUTH_USERNAME} -p ${REGISTRY_AUTH_PASSWORD}
        //             echo ${SSH_PASSWORD} | sudo -S docker pull ${DOCKER_IMAGE_NAME}
        //             echo ${SSH_PASSWORD} | sudo -S docker run -d --rm --name pygoat -p 8000:8000 ${DOCKER_IMAGE_NAME} 
        //             """
        //     }            
        // }        

        // stage('Zap') {
        //      when {
        //         expression { false }
        //     }
        //     agent {
        //         label 'dnd'
        //     }
        //     steps {
        //         sh 'pwd'
        //         //sh 'touch ./report.html'
        //         //sh 'touch ./gen.conf'
        //         //sh 'chmod a+w ./report.html'
        //         //sh 'touch ./gen.conf'
        //         script {
        //              def currentDir = sh(script: 'pwd', returnStdout: true).trim()
        //              def zapCommand = "docker run -v ${currentDir}:/zap/wrk/:rw --user root -t ghcr.io/zaproxy/zaproxy:stable zap-baseline.py  -t http://192.168.0.101:8000 -g /zap/wrk/gen.conf -r /zap/wrk/zap-report.html -j /zap/wrk/zap-report.json -l FAIL"
        //              echo "Running ZAP command: ${zapCommand}"
        //              def zapResult = sh(script: zapCommand, returnStatus: true)
                    
        //              echo "ZAP Scan Output: ${zapResult}"

        //              if (zapResult == '1') {
        //                  error("ZAP scan failed with return code 1")
        //              }          

        //              stash name: 'zap-report', includes: 'zap-report.json'
        //         }

        //         sh 'ls -lt'

        //         archiveArtifacts artifacts: 'zap-report.html,gen.conf,zap-report.json', allowEmptyArchive: true         
        //     }            
        // }        

        // stage('Zap2') {
        //      when {
        //         expression { false }
        //     }
        //     agent {
        //         label 'alpinejdk17'
        //     }    

        //     steps {
        //         sh 'pwd'
        //         sh 'java --version'
        //         sh 'curl -L -o ZAP_2.15.0_Linux.tar.gz https://github.com/zaproxy/zaproxy/releases/download/v2.15.0/ZAP_2.15.0_Linux.tar.gz'
        //         sh 'tar -xzf ZAP_2.15.0_Linux.tar.gz'
        //         sh './ZAP_2.15.0/zap.sh -cmd -addonupdate -addoninstall wappalyzer -addoninstall pscanrulesBeta'
        //         sh 'ls -lt'            
        //         sh './ZAP_2.15.0/zap.sh -cmd -quickurl http://192.168.0.101:8000 -quickout $(pwd)/zapsh-report.json'
        //         sh 'ls -lt'
        //         sh 'cat ./zapsh-report.json'
        //         stash name: 'zapsh-report', includes: 'zapsh-report.json'
        //         archiveArtifacts artifacts: 'zapsh-report.json', allowEmptyArchive: true         
        //     }            
        // }        

        // stage('Destroy') {
        //     when {
        //         expression { false }
        //     }
        //     steps {
        //         sh 'apt update && apt install -y sshpass'
        //         sh """
        //             sshpass -p 'kali' ssh -o StrictHostKeyChecking=no -p 2222 kali@192.168.0.101 <<EOF
        //             echo ${SSH_PASSWORD} | sudo -S docker ps
        //             echo ${SSH_PASSWORD} | sudo docker -S image ls
        //             echo ${SSH_PASSWORD} | sudo -S docker stop pygoat || true
        //             echo ${SSH_PASSWORD} | sudo -S docker ps
        //             echo ${SSH_PASSWORD} | sudo -S docker image ls
        //             EOF
        //             """                    
        //     }
        // }                
        // stage('ZapQG') {
        //     when {
        //         expression { false }
        //     }
        //     steps {
        //          unstash 'zapsh-report'
        //          sh 'ls -lth'
        //         script {
        //             def jsonText = readFile 'zapsh-report.json'
        //             def json = new groovy.json.JsonSlurper().parseText(jsonText)
        //             int totalSum = 0
        //             json.site.each { site ->
        //                 site.alerts.each { alert ->
        //                     totalSum += alert.count.toInteger()
        //                 }
        //             }
        //             echo "Sum of counts: ${totalSum}"
        //         }
        //     }
        // }     

        // stage('CheckVault') {
        //     agent {
        //         label 'dnd'
        //     }
        //     when {
        //         expression { false }
        //     }

        //     steps {
        //         script {
        //             def secrets = [
        //                 [path: 'labs/hub', engineVersion: 1, 
        //                 secretValues: [
        //                     [envVar: 'hub_login', vaultKey: 'login'],
        //                     [envVar: 'hub_password', vaultKey: 'password']]]
        //             ]
        //             def configuration = [vaultUrl: 'http://192.168.0.101:8205',
        //                  vaultCredentialId: 'vault_token',
        //                  engineVersion: 1]
        //             withVault([configuration: configuration, vaultSecrets: secrets]) {
        //                 sh 'echo $hub_login'
        //                 sh 'echo $hub_password'
        //                 env.hub_login = hub_login
        //                 env.hub_password = hub_password
        //             }                    
        //         }

        //         sh 'docker login -u ${hub_login} -p ${hub_password}'
        //     }
        // }        

        // stage('SASTSemGrepQG') {
        //     agent {
        //         label 'alpinejdk17'
        //     }
        //     when {
        //         expression { false }
        //     }
        //     steps {
        //         unstash 'semgrep-report'
        //         sh 'ls -lth'
        //         script {
        //             def jsonText = readFile env.SEMGREP_REPORT
        //             def json = new groovy.json.JsonSlurper().parseText(jsonText)
        //             int errorCount = 0
        //             json.results.each { r ->
        //                 if (r.extra.severity == "ERROR") {
        //                     errorCount+=1;
        //                 }
        //             }
        //             echo "Errors: ${errorCount}"
        //             if (errorCount > env.SEMGREP_REPORT_MAX_ERROR.toInteger()) {
        //                 error("SEMGREP QG failed.")
        //             }
        //         }
        //     }
        // }   

        // stage('SCA') {
        //     agent {
        //         label 'dnd'
        //     }
        //     when {
        //         expression { true }
        //     }

        //     steps {
        //         sh '''
        //             #echo '192.168.5.13 harbor.cyber-ed.labs' >> /etc/hosts
        //             sudo curl -sSfL https://raw.githubusercontent.com/anchore/grype/main/install.sh | sudo sh -s -- -b /usr/local/bin
        //             sudo grype docker:podkatilovas/pygoat:113 -o table >> ${SCA_REPORT}
        //             ls -lt
        //         '''
        //         stash name: 'semgrep-report', includes: "${SCA_REPORT}"
        //         archiveArtifacts artifacts: "${SCA_REPORT}", allowEmptyArchive: true
        //     }
        // }                             
    }
}
