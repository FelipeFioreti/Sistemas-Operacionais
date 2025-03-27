#include <stdio.h>
#include <stdlib.h>
#include <security/pam_appl.h>
#include <string.h>

// Função de conversação do PAM
int custom_conv(int num_msg, const struct pam_message **msg,
                struct pam_response **resp, void *appdata_ptr) {
    struct pam_response *responses = malloc(num_msg * sizeof(struct pam_response));
    if (responses == NULL) {
        return PAM_CONV_ERR;
    }

    for (int i = 0; i < num_msg; i++) {
        char input[256];

        // Se o PAM pedir o nome do usuário e appdata_ptr estiver definido, usamos ele
        if (msg[i]->msg_style == PAM_PROMPT_ECHO_ON && appdata_ptr != NULL) {
            responses[i].resp = strdup((char *)appdata_ptr);
        } else {
            // Coleta a entrada manualmente
            if (msg[i]->msg_style == PAM_PROMPT_ECHO_OFF) {
                system("stty -echo");  // Desativa exibição da senha
            }

            printf("%s", msg[i]->msg);
            fgets(input, sizeof(input), stdin);

            if (msg[i]->msg_style == PAM_PROMPT_ECHO_OFF) {
                system("stty echo");  // Reativa terminal
                printf("\n");
            }

            input[strcspn(input, "\n")] = 0;  // Remove "\n" do final da string
            responses[i].resp = strdup(input);
        }

        responses[i].resp_retcode = 0;
    }

    *resp = responses;
    return PAM_SUCCESS;
}

int main() {
    pam_handle_t *pamh;
    const char *usuario = "luiz";  // Usuário fixo

    // Configuração da estrutura de conversação
    struct pam_conv conv = { custom_conv, (void *)usuario };

    // Inicia o PAM com o nome de usuário fixo
    if (pam_start("login", usuario, &conv, &pamh) != PAM_SUCCESS) {
        fprintf(stderr, "Erro ao iniciar PAM\n");
        return 1;
    }

    // Força o uso do usuário, evitando múltiplas requisições
    pam_set_item(pamh, PAM_USER, usuario);

    // Autentica o usuário
    int resultado = pam_authenticate(pamh, 0);
    if (resultado == PAM_SUCCESS) {
        printf("Autenticação bem-sucedida!\n");
    } else {
        printf("Falha na autenticação.\n");
    }

    pam_end(pamh, resultado);
    return (resultado == PAM_SUCCESS) ? 0 : 1;
}