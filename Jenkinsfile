pipeline {
  agent none
  environment {
    ACTUAL_BRANCH = "${env.CHANGE_BRANCH ?: env.BRANCH_NAME}"
  }

  stages {
    stage('Build Bundles') {
      parallel {
        stage('Linux-3.6') {
          agent {
            kubernetes {
              cloud 'eks-swimlane-io'
              label "jenkins-k8s-${UUID.randomUUID().toString()}"
              yaml """
kind: Pod
metadata:
  name: jenkins-k8s
spec:
  containers:
  - name: jnlp
    image: 'jenkins/jnlp-slave:latest'
  - name: python
    image: 'python:3.6.0'
    command: ["tail", "-f", "/dev/null"]
    resources:
      requests:
        memory: "700Mi"
        cpu: "700m"
      limits:
        memory: "900Mi"
        cpu: "900m"
  imagePullSecrets:
  - name: swimlane-nexus
"""
            }
          }
          stages {            
            stage('Install Dependencies') {
              steps {
                container("python"){
                  retry(2) {
                    sh """
                    pip install wheel
                    pip install -r requirements.txt                    
                    """
                  }
                }
              }
            }

            stage('Build') {
              steps {
                container("python"){
                  sh """
                    ./build.sh
                    """
                }
              }
            }

            stage('Cleanup') {
                steps{
                    cleanWs()
                    }
                }
            stage('Start Test Job'){
              steps{
                build job:'Email Master Test'
              }
            }
          }
        }
      }
    }
  }
  post {
    failure {
      slackSend(
        baseUrl: 'https://swimlane.slack.com/services/hooks/jenkins-ci/',
        channel: '#surf',
        color: 'danger',
        message: "EmailMaster branch `${env.ACTUAL_BRANCH}` <${env.RUN_DISPLAY_URL}|Build #${env.BUILD_NUMBER}> failed",
        teamDomain: 'swimlane',
        tokenCredentialId: 'slack-token')
    }
    success {
      // Post successful notification when failing branch has been fixed
      script {
        if (currentBuild.getPreviousBuild() &&
            currentBuild.getPreviousBuild().getResult().toString() != "SUCCESS") {
          slackSend(
            baseUrl: 'https://swimlane.slack.com/services/hooks/jenkins-ci/',
            channel: '#surf',
            color: 'good',
            message: "EmailMaster branch `${env.ACTUAL_BRANCH}` <${env.RUN_DISPLAY_URL}|Build #${env.BUILD_NUMBER}> fixed",
            teamDomain: 'swimlane',
            tokenCredentialId: 'slack-token')
        }
      }
    }
  }
}