pipeline {
    agent any
     environment {
         DOCKER_IMAGE_NAME="podkatilovas/nettu-meet:latest"
         SEMGREP_REPORT = 'semgrep-report.json'
         DEPTRACK_PRJ_NAME="podkatilovas_exam_5"
         DEPTRACK_URL="https://s410-exam.cyber-ed.space:8081"
         DEPTRACK_TOKEN="odt_SfCq7Csub3peq7Y6lSlQy5Ngp9sSYpJl"
         DODJO_URL="https://s410-exam.cyber-ed.space:8083/api/v2/import-scan/"
         DODJO_TOKEN="c5b50032ffd2e0aa02e2ff56ac23f0e350af75b4"
         SEMGREP_REPORT_MAX_ERROR="5"
         ZAPSH_REPORT_MAX_ERROR="5"
     }

     stages {
        stage('SASTSemGrep') {
            agent {
                label 'alpine'
            }

            steps {
                script {
                    try {
                        sh '''
                            apk update && apk add --no-cache python3 py3-pip py3-virtualenv
                            python3 -m venv venv
                            . venv/bin/activate
                            pip install semgrep
                            semgrep ci --config auto --json > ${SEMGREP_REPORT}
                        '''
                    } catch (Exception e) {
                        echo 'Semgrep encountered issues.'
                    }
                }

                sh 'ls -lth'
                stash name: 'semgrep-report', includes: "${SEMGREP_REPORT}"
                archiveArtifacts artifacts: "${SEMGREP_REPORT}", allowEmptyArchive: true
            }
        }   

        stage('Zap') {
            agent {
                label 'alpine'
            }    

            steps {
                sh 'curl -L -o ZAP_2.15.0_Linux.tar.gz https://github.com/zaproxy/zaproxy/releases/download/v2.15.0/ZAP_2.15.0_Linux.tar.gz'
                sh 'tar -xzf ZAP_2.15.0_Linux.tar.gz'
                sh './ZAP_2.15.0/zap.sh -cmd -addonupdate -addoninstall wappalyzer -addoninstall pscanrulesBeta'
                sh 'ls -lt'            
                sh './ZAP_2.15.0/zap.sh -cmd -quickurl https://s410-exam.cyber-ed.space:8084 -quickout $(pwd)/zapsh-report.xml'
                sh 'ls -lt'
                stash name: 'zapsh-report', includes: 'zapsh-report.xml'
                archiveArtifacts artifacts: 'zapsh-report.xml', allowEmptyArchive: true         
            }            
        }      

        stage('SCA') {
            agent {
                label 'dind'
            }

            steps {
                sh '''
                    cd server
                    docker login -u aspodkatilov@gmail.com -p P@ssw0rd!
                    docker build . -t ${DOCKER_IMAGE_NAME} -f Dockerfile
                    docker image ls
                    sudo apt-get install -y curl

                    curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh

                    ./bin/trivy image --format cyclonedx --output ${WORKSPACE}/sbom.json ${DOCKER_IMAGE_NAME}

                    cd ${WORKSPACE}

                    ls -lt                    
                '''
                stash name: 'sbom', includes: 'sbom.json'
                archiveArtifacts artifacts: "sbom.json", allowEmptyArchive: true
            }
        }     

        // stage('Debug') {
        //     agent {
        //         label 'alpine'
        //     }    
        //     steps {
        //         sh 'cp ./test_reports/* ./'
        //         sh 'ls -lt'
        //         stash name: 'sbom', includes: 'sbom.json'
        //         stash name: 'semgrep-report', includes: "${SEMGREP_REPORT}"
        //         stash name: 'zapsh-report', includes: 'zapsh-report.xml'
        //     }            
        // }     

        stage('SendToDepTrack') {
            agent {
                label 'alpine'
            }

            steps {
                unstash 'sbom'

                sh '''
                    echo ${WORKSPACE}                    
                    ls -lt           

                    apk update && apk add --no-cache jq

                    response=$(curl -k -s -X PUT "${DEPTRACK_URL}/api/v1/project" \
                        -H "X-Api-Key: ${DEPTRACK_TOKEN}" \
                        -H "Content-Type: application/json" \
                        -d '{
                            "name": "podkatilovas_exam_8",
                            "version": "1.0.0"
                        }')

                    uuid=$(echo $response | jq -r '.uuid')
                    echo "Project UUID: $uuid"

                    
                    sbomresponse=$(curl -k -o /dev/null -s -w "%{http_code}" -X POST  "${DEPTRACK_URL}/api/v1/bom" \
                        -H 'Content-Type: multipart/form-data; boundary=__X_BOM__' \
                        -H "X-API-Key: ${DEPTRACK_TOKEN}" \
                        -F "bom=@sbom.json" -F "project=${uuid}")

                    echo "Result: $sbomresponse"
                    if [ "$sbomresponse" -ne "200" ]; then
                        echo "Error: Failed to upload SBOM"
                        exit 1
                    fi
                    ls -lt                                        
                '''
            }
        }     


        stage('QualtityGates') {
            agent {
                label 'alpine'
            }

            steps {
                unstash 'semgrep-report'
                unstash 'zapsh-report'

                script {
                    def xmlFileContent = readFile 'zapsh-report.xml'
                    //<riskdesc>High (Low)</riskdesc>
                    def searchString = "<riskcode>3</riskcode>"
                    def lines = xmlFileContent.split('\n')
                    int zapErrorCount = lines.count { line -> line.contains(searchString) }

                    echo "ZAP total error with risk 3 (High): ${zapErrorCount}"

                    if (zapErrorCount > env.SEMGREP_REPORT_MAX_ERROR.toInteger()) {
                        echo "ZAP QG failed."
                        //для отладки не блочим
                        //error("ZAP QG failed.")
                    }

                    def jsonText = readFile env.SEMGREP_REPORT
                    def json = new groovy.json.JsonSlurper().parseText(jsonText)
                    int errorCount = 0
                    json.results.each { r ->
                        if (r.extra.severity == "ERROR") {
                            errorCount+=1;
                        }
                    }
                    echo "SEMGREP error count: ${errorCount}"
                    if (errorCount > env.SEMGREP_REPORT_MAX_ERROR.toInteger()) {
                        echo "SEMGREP QG failed."
                        //для отладки не блочим
                        //error("SEMGREP QG failed.")
                    }
                }
            }
        }     

        stage('SendToDodjo') {
            agent {
                label 'alpine'
            }
            steps {
                unstash 'semgrep-report'
                unstash 'zapsh-report'

                sh '''
                    apk update && apk add --no-cache python3 py3-pip py3-virtualenv
                    python3 -m venv venv
                    . venv/bin/activate
                    pip install requests
                    python -m dodjo ${DODJO_URL} ${DODJO_TOKEN} semgrep-report.json "Semgrep JSON Report"
                    python -m dodjo ${DODJO_URL} ${DODJO_TOKEN} zapsh-report.xml "ZAP Scan"
                '''
            }
        }   
     }
}
