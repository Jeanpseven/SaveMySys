import psutil
import os
import win32security
import ntsecuritycon

def detectar_processos_suspeitos():
    processos_suspeitos = []
    for processo in psutil.process_iter(['pid', 'name', 'username', 'cmdline']):
        if processo.info['username'] != 'SYSTEM':  # Ignorar processos do sistema
            if processo.info['name'] == 'cmd.exe' and len(processo.info['cmdline']) == 1:
                processos_suspeitos.append(processo)
    return processos_suspeitos

def encerrar_processo(pid):
    try:
        processo = psutil.Process(pid)
        processo.terminate()
        return True
    except psutil.NoSuchProcess:
        return False

def bloquear_acesso_executavel(executavel):
    try:
        sd = win32security.GetFileSecurity(executavel, win32security.DACL_SECURITY_INFORMATION)
        dacl = sd.GetSecurityDescriptorDacl()
        dacl.AddAccessDeniedAce(win32security.ACL_REVISION, ntsecuritycon.FILE_GENERIC_EXECUTE, win32security.SECURITY_WORLD_SID_AUTHORITY, win32security.ACCESS_DENIED)
        sd.SetSecurityDescriptorDacl(1, dacl, 0)
        win32security.SetFileSecurity(executavel, win32security.DACL_SECURITY_INFORMATION, sd)
        return True
    except Exception as e:
        print(f'Falha ao bloquear o acesso ao executável: {str(e)}')
        return False

def main():
    processos_suspeitos = detectar_processos_suspeitos()

    if not processos_suspeitos:
        print('Nenhum processo suspeito encontrado.')
        return

    print('Processos suspeitos encontrados:')
    for i, processo in enumerate(processos_suspeitos, start=1):
        print(f'{i}. PID: {processo.info["pid"]} - Nome: {processo.info["name"]} - Usuário: {processo.info["username"]}')

    opcao = input('Deseja encerrar e bloquear algum processo suspeito? (S/N): ')
    if opcao.upper() == 'S':
        numero_processo = int(input('Informe o número do processo a ser encerrado e bloqueado: '))

        if 1 <= numero_processo <= len(processos_suspeitos):
            processo_escolhido = processos_suspeitos[numero_processo - 1]
            pid = processo_escolhido.info['pid']
            executavel = processo_escolhido.exe()

            encerrado = encerrar_processo(pid)
            if encerrado:
                bloqueado = bloquear_acesso_executavel(executavel)
                if bloqueado:
                    print(f'Processo {pid} encerrado e bloqueado com sucesso.')
                else:
                    print(f'Falha ao bloquear o acesso ao executável do processo {pid}.')
            else:
                print(f'Falha ao encerrar o processo {pid}.')
        else:
            print('Número de processo inválido.')
    else:
        print('Nenhum processo encerrado e bloqueado.')

if __name__ == '__main__':
    main()
