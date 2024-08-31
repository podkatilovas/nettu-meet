pipeline {
    agent any
     environment {
         DOCKER_IMAGE_NAME="podkatilovas/nettu-meet:latest"
         SEMGREP_REPORT = 'semgrep-report.json'
         DEPTRACK_PRJ_NAME="podkatilovas_exam_3"
         DEPTRACK_URL="https://s410-exam.cyber-ed.space:8081"
         DEPTRACK_TOKEN="odt_SfCq7Csub3peq7Y6lSlQy5Ngp9sSYpJl"
         DODJO_URL="https://s410-exam.cyber-ed.space:8083/api/v2/import-scan/"
         DODJO_TOKEN="c5b50032ffd2e0aa02e2ff56ac23f0e350af75b4"
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

        // stage('SCA') {
        //     agent {
        //         label 'dind'
        //     }

        //     steps {
        //         sh '''
        //             cd server
        //             docker build . -t ${DOCKER_IMAGE_NAME} -f Dockerfile
        //             docker image ls
        //             sudo apt-get install -y curl

        //             curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh

        //             ./bin/trivy image --format json --output ${WORKSPACE}/sbom.json ${DOCKER_IMAGE_NAME}

        //             cd ${WORKSPACE}

        //             ls -lt                    
        //         '''
        //         stash name: 'sbom', includes: 'sbom.json'
        //         archiveArtifacts artifacts: "sbom.json", allowEmptyArchive: true
        //     }
        // }     

        stage('Debug') {
            agent {
                label 'alpine'
            }    
            steps {
                sh 'cp ./test_reports/* ./'
                sh 'ls -lt'
                stash name: 'sbom', includes: 'sbom.json'
                stash name: 'semgrep-report', includes: "${SEMGREP_REPORT}"
                stash name: 'zapsh-report', includes: 'zapsh-report.json'
            }            
        }     

        stage('SendToDepTrack') {
            agent {
                label 'alpine'
            }

            steps {
                unstash 'sbom'

                sh '''
                    echo ${WORKSPACE}
                    ls -lt
                    response=$(curl -k -s -X PUT "${DEPTRACK_URL}/api/v1/project" \
                        -H "X-Api-Key: ${DEPTRACK_TOKEN}" \
                        -H "Content-Type: application/json" \
                        -d '{
                            "name": "podkatilovas_exam_3",
                            "version": "1.0.0"
                        }')

                    uuid=$(echo $response | jq -r '.uuid')
                    echo "Project UUID: $uuid"

                    sbomresponse = $(curl -k -X POST "${DEPTRACK_URL}/api/v1/project/${uuid}/sbom" \
                         -H "X-Api-Key: ${DEPTRACK_TOKEN}" \
                         -H "Content-Type: application/json" \
                         -F "file=@sbom.json")

                    http_code=${response: -3}

                    echo "Result = $http_code"

                    if [ "$http_code" -ne 200 ]; then
                        echo "Error: Failed to upload SBOM"
                        exit 1
                    fi
                    ls -lt                                        
                '''
            }
        }     


        // stage('QualtityGates') {
        //     agent {
        //         label 'alpine'
        //     }

        //     steps {
        //         unstash 'zapsh-report'
        //     }
        // }     


        // stage('SendToDodjo') {
        //     agent {
        //         label 'alpine'
        //     }
        //     steps {
        //         unstash 'semgrep-report'
        //         unstash 'zapsh-report'

        //         sh '''
        //             apk update && apk add --no-cache python3 py3-pip py3-virtualenv
        //             python3 -m venv venv
        //             . venv/bin/activate
        //             python -m dodgo ${DODJO_URL} ${DODJO_TOKEN} semgrep-report.json "Semgrep JSON Report"
        //             python -m dodgo ${DODJO_URL} ${DODJO_TOKEN} zapsh-report.json "ZAP Scan"
        //         '''
        //         }
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
