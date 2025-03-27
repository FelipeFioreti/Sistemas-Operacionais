#include <security/pam_appl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/*Função de conversação */
int custom_conv(int num_msg, const struct pam_message msg,
                struct pam_response resp, voidappdata_ptr) {
    struct pam_response responses = malloc(num_msg sizeof(struct pam_response));
    if (responses == NULL) {
        return PAM_CONV_ERR;
    }

    for (int i = 0; i < num_msg; i++) {
        if (msg[i]->msg_style == PAM_PROMPT_ECHO_ON || msg[i]->msg_style == PAM_PROMPT_ECHO_OFF) {
            char input[256];
            printf("%s", msg[i]->msg);
            if (msg[i]->msg_style == PAM_PROMPT_ECHO_OFF) {
                system("stty -echo");  // Desativar eco para senhas
            }
            fgets(input, sizeof(input), stdin);
            if (msg[i]->msg_style == PAM_PROMPT_ECHO_OFF) {
                system("stty echo");   // Reativar eco
                printf("\n");
            }
            input[strcspn(input, "\n")] = 0;  // Remover quebra de linha

            responses[i].resp = strdup(input);
            responses[i].resp_retcode = 0;
        } else {
            responses[i].resp = NULL;
            responses[i].resp_retcode = 0;
        }
    }

    resp = responses;
    return PAM_SUCCESS;
}

int main() {
    struct pam_conv conv = { custom_conv, NULL };
    pam_handle_tpamh = NULL;
    int ret = pam_start("example", NULL, &conv, &pamh);

    if (ret != PAM_SUCCESS) {
        fprintf(stderr, "Erro ao iniciar PAM: %s\n", pam_strerror(pamh, ret));
        return 1;
    }

    ret = pam_authenticate(pamh, 0);
    if (ret == PAM_SUCCESS) {
        printf("Autenticação bem-sucedida!\n");
    } else {
        printf("Falha na autenticação: %s\n", pam_strerror(pamh, ret));
    }

    pam_end(pamh, ret);
    return (ret == PAM_SUCCESS) ? 0 : 1;
}
