#!/bin/bash

# Script para restaurar o acesso SFTP em uma VPS Debian/Ubuntu
# Aborda problemas comuns como 'Received message too long' e configurações incorretas do SSH/SFTP.
# Compatível com Debian e Ubuntu.

# --- Funções de utilidade ---

log_message() {
    echo "[$(date +'%Y-%m-%d %H:%M:%S')] $1"
}

backup_file() {
    local file="$1"
    if [ -f "$file" ]; then
        log_message "Fazendo backup de $file para ${file}.bak"
        cp "$file" "${file}.bak"
    else
        log_message "Arquivo $file não encontrado, pulando backup."
    fi
}

# --- Correção do sshd_config ---

fix_sshd_config() {
    log_message "Verificando e corrigindo /etc/ssh/sshd_config..."
    local sshd_config="/etc/ssh/sshd_config"
    backup_file "$sshd_config"

    # Garante que o subsistema SFTP esteja configurado corretamente
    if ! grep -q "^Subsystem\s*sftp" "$sshd_config"; then
        log_message "Adicionando ou corrigindo a linha Subsystem sftp no sshd_config."
        # Remove linhas existentes que começam com Subsystem sftp e adiciona a correta
        sed -i '/^Subsystem\s*sftp/d' "$sshd_config"
        echo "Subsystem sftp /usr/lib/openssh/sftp-server" >> "$sshd_config"
    elif ! grep -q "^Subsystem\s*sftp\s*/usr/lib/openssh/sftp-server" "$sshd_config"; then
        log_message "Corrigindo o caminho do Subsystem sftp no sshd_config."
        sed -i 's/^Subsystem\s*sftp.*/Subsystem sftp \/usr\/lib\/openssh\/sftp-server/' "$sshd_config"
    else
        log_message "Subsystem sftp já está configurado corretamente no sshd_config."
    fi

    # Opcional: Garantir PasswordAuthentication yes se for o método de autenticação principal
    # CUIDADO: Mudar isso pode afetar a segurança se você usa apenas chaves SSH.
    # if grep -q "^#PasswordAuthentication yes" "$sssd_config"; then
    #     log_message "Descomentando PasswordAuthentication no sshd_config."
    #     sed -i 's/^#PasswordAuthentication yes/PasswordAuthentication yes/' "$sshd_config"
    # elif grep -q "^PasswordAuthentication no" "$sssd_config"; then
    #     log_message "Alterando PasswordAuthentication para yes no sshd_config."
    #     sed -i 's/^PasswordAuthentication no/PasswordAuthentication yes/' "$sshd_config"
    # fi

    log_message "Configuração do sshd_config verificada."
}

# --- Correção de arquivos de configuração do shell (para 'Received message too long') ---

add_interactive_check() {
    local file="$1"
    
    if [ -f "$file" ]; then
        log_message "Verificando $file para saída em sessões não interativas..."
        # Verifica se a verificação já existe usando grep -F para strings fixas
        if ! grep -Fq "case $- in *i*) ;; *) return;; esac" "$file" && \
           ! grep -Fq "if [ -z \"$PS1\" ]; then" "$file" && \
           ! grep -Fq "if [ -z \"$TERM\" ]; then" "$file"; then
            
            log_message "Adicionando verificação de sessão interativa a $file..."
            backup_file "$file"
            
            # Adiciona a verificação no início do arquivo
            (echo "# Se não for uma sessão interativa, saia"; \
             echo "case $- in *i*) ;; *) return;; esac"; \
             cat "$file") > "${file}.tmp" && mv "${file}.tmp" "$file"
            
            log_message "$file atualizado com sucesso."
        else
            log_message "Verificação de sessão interativa já existe em $file. Nenhuma alteração necessária."
        fi
    else
        log_message "Arquivo $file não encontrado. Pulando."
    fi
}

fix_shell_configs() {
    log_message "Iniciando correção de arquivos de configuração do shell..."
    local shell_config_files=("$HOME/.bashrc" "$HOME/.profile" "$HOME/.zshrc")

    for config_file in "${shell_config_files[@]}"; do
        add_interactive_check "$config_file"
    done
    log_message "Correção de arquivos de configuração do shell concluída."
}

# --- Correção de permissões SSH ---

fix_ssh_permissions() {
    log_message "Verificando e corrigindo permissões de diretórios e arquivos SSH..."
    local ssh_dir="$HOME/.ssh"

    if [ -d "$ssh_dir" ]; then
        log_message "Definindo permissões para $ssh_dir (0700)."
        chmod 0700 "$ssh_dir"
    else
        log_message "Diretório $ssh_dir não encontrado. Criando com permissões 0700."
        mkdir -p -m 0700 "$ssh_dir"
    fi

    local authorized_keys="$ssh_dir/authorized_keys"
    if [ -f "$authorized_keys" ]; then
        log_message "Definindo permissões para $authorized_keys (0600)."
        chmod 0600 "$authorized_keys"
    else
        log_message "Arquivo $authorized_keys não encontrado. Se você usa chaves SSH, certifique-se de que ele exista e tenha as permissões corretas."
    fi
    log_message "Permissões SSH verificadas."
}

# --- Reiniciar serviço SSH ---

restart_ssh_service() {
    log_message "Reiniciando o serviço SSH..."
    if command -v systemctl &> /dev/null; then
        systemctl restart sshd
        log_message "Serviço SSH reiniciado via systemctl."
    elif command -v service &> /dev/null; then
        service ssh restart
        log_message "Serviço SSH reiniciado via service."
    else
        log_message "Não foi possível encontrar systemctl ou service para reiniciar o SSH. Por favor, reinicie manualmente."
    fi
}

# --- Execução principal ---

log_message "Iniciando o script de restauração do SFTP."

# Verifique se o script está sendo executado como root
if [ "$(id -u)" -ne 0 ]; then
    log_message "Este script precisa ser executado como root. Por favor, use 'sudo ./restore_sftp_access.sh'."
    exit 1
fi

fix_sshd_config
fix_shell_configs
fix_ssh_permissions
restart_ssh_service

log_message "Script de restauração do SFTP concluído. Por favor, tente sua conexão SFTP novamente."


