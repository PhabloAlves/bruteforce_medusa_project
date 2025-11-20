Ataque Brute Force com Medusa e Kali Linux

## 📋 Descrição do Projeto

Este projeto apresenta uma análise prática de segurança cibernética focada em ataques de força bruta (brute force), desenvolvido em ambiente controlado para fins exclusivamente educacionais. Utilizando a ferramenta Medusa em conjunto com o Kali Linux, foram simulados cenários reais de ataque contra o sistema Metasploitable 2, abrangendo três vetores distintos: serviço FTP (File Transfer Protocol), formulário web através do DVWA (Damn Vulnerable Web Application) e protocolo SMB (Server Message Block).

O ambiente foi estruturado em máquinas virtuais isoladas no VirtualBox, configuradas em rede host-only para garantir total segurança durante os testes. Foram desenvolvidas wordlists simplificadas e customizadas especificamente para fins didáticos, permitindo demonstrar de forma clara e objetiva como vulnerabilidades de autenticação podem ser exploradas através de ataques automatizados.

Além da execução prática dos ataques, o projeto documenta detalhadamente todo o processo técnico, desde a configuração inicial do ambiente até a análise dos resultados obtidos, incluindo propostas de medidas de mitigação e boas práticas de segurança. O objetivo principal é proporcionar uma compreensão profunda sobre vulnerabilidades de autenticação, técnicas de auditoria de segurança ofensiva e, principalmente, como proteger sistemas contra esse tipo de ameaça no mundo real.

**Aviso:** Todas as atividades foram realizadas em ambiente isolado e controlado, respeitando princípios éticos do hacking responsável.

## 🎯 Objetivos de Aprendizagem

- Compreender o funcionamento técnico de ataques de força bruta em diferentes protocolos
- Dominar o uso do Kali Linux e da ferramenta Medusa em cenários práticos
- Desenvolver habilidades de documentação técnica em segurança da informação
- Identificar falhas comuns de configuração e autenticação em sistemas
- Aprender a propor contramedidas efetivas para proteger ambientes corporativos
- Aplicar princípios éticos de hacking em ambiente controlado

## 🛠️ Tecnologias Utilizadas

- **Sistema Operacional:** Kali Linux
- **Ferramenta Principal:** Medusa
- **Ambiente de Testes:** Metasploitable 2 / DVWA
- **Virtualização:** VirtualBox

## 🎭 Cenários de Ataque Simulados

### Preparação Inicial do Ambiente

Antes de iniciar qualquer teste de penetração, é fundamental estabelecer a comunicação entre as máquinas e identificar o alvo. Para isso, o primeiro passo consistiu em inicializar a máquina virtual Metasploitable 2 e obter seu endereço IP na rede interna.

#### Identificação do Alvo

Com a VM Metasploitable em execução, foi utilizado o seguinte comando no terminal da máquina alvo para identificar seu endereço IP:
```bash
ip a
```

**Endereço IP identificado:** `192.168.56.101`

Este IP será utilizado como alvo em todos os cenários de ataque subsequentes.

---

#### Varredura de Portas e Serviços

Após identificar o IP do alvo, foi realizada uma varredura completa para identificar portas abertas e serviços ativos no sistema. Esta etapa é fundamental para mapear a superfície de ataque disponível.

**Comando executado:**
```bash
nmap -sV -p 21,80,139,445 192.168.56.101
```

**Explicação dos parâmetros:**
- `-sV`: Detecta versões dos serviços em execução
- `-p 21,80,139,445`: Especifica as portas a serem escaneadas:
  - **21**: FTP (File Transfer Protocol)
  - **80**: HTTP (Web)
  - **139**: NetBIOS/SMB
  - **445**: SMB (Server Message Block)
- `192.168.56.101`: Endereço IP do alvo

**Resultado da varredura:**

✅ **Serviços identificados:**
- **Porta 21:** vsftpd 2.3.4 (FTP)
- **Porta 80:** Apache httpd 2.2.8 (HTTP)
- **Porta 139:** Samba smbd 3.X (NetBIOS)
- **Porta 445:** Samba smbd 3.X (SMB)

Todos os serviços identificados estão ativos e acessíveis, confirmando os vetores de ataque que serão explorados nos cenários subsequentes.

---

### Cenário 1: Ataque de Força Bruta em FTP

#### Objetivo

Demonstrar como um atacante pode comprometer o serviço FTP através de tentativas automatizadas de autenticação, explorando senhas fracas ou padrões inseguros.

#### Fase 1: Criação das Wordlists

Para realizar o ataque de força bruta, foram criadas duas wordlists personalizadas contendo usuários e senhas comuns. Por se tratar de um ambiente didático, as listas foram mantidas intencionalmente pequenas para agilizar o processo e facilitar a compreensão.

**Criação da lista de usuários:**
```bash
echo -e 'user\nmsfadmin\nadmin\nroot' > users.txt
```

**Conteúdo do arquivo `users.txt`:**
```
user
msfadmin
admin
root
```

**Criação da lista de senhas:**
```bash
echo -e '123456\npassword\nqwerty\nmsfadmin' > passwords.txt
```

**Conteúdo do arquivo `passwords.txt`:**
```
123456
password
qwerty
msfadmin
```

> **Nota:** Em cenários reais, atacantes utilizam wordlists muito mais extensas, contendo milhares ou milhões de combinações possíveis, incluindo variações, dicionários e senhas vazadas em data breaches.

---

#### Fase 2: Execução do Ataque de Força Bruta

Com as wordlists preparadas e o serviço FTP confirmado, foi executado o ataque utilizando a ferramenta **Medusa**, que testa sistematicamente todas as combinações de usuário e senha.

**Comando executado:**
```bash
medusa -h 192.168.56.101 -U users.txt -P passwords.txt -M ftp -t 6
```

**Explicação dos parâmetros:**
- `-h 192.168.56.101`: Define o host (IP) alvo do ataque
- `-U users.txt`: Especifica o arquivo contendo a lista de usuários
- `-P passwords.txt`: Especifica o arquivo contendo a lista de senhas
- `-M ftp`: Define o módulo de ataque (protocolo FTP)
- `-t 6`: Estabelece 6 threads paralelas para acelerar o processo

**Como funciona:**

O Medusa realiza tentativas de login combinando cada usuário da lista com cada senha da lista, de forma automatizada e paralela. O processo continua até que todas as combinações sejam testadas ou até que credenciais válidas sejam encontradas.

**Resultado do ataque:**

![Saída mostrando login e senha encontrados no FTP](images/login_password_found_ftp_2.png)

✅ **Credenciais comprometidas:**
- **Usuário:** `msfadmin`
- **Senha:** `msfadmin`

---

#### Fase 3: Validação do Acesso

Para confirmar o sucesso do ataque, foi realizada uma conexão legítima ao servidor FTP utilizando as credenciais obtidas.

**Comando executado:**
```bash
ftp 192.168.56.101
```

Ao executar o comando, o sistema solicitou as credenciais de autenticação:
```
Name: msfadmin
Password: msfadmin
```

**Resultado:**
![Acesso bem-sucedido ao servidor FTP](images/ftp_accessed_3.png)

✅ **Acesso confirmado:** Login realizado com sucesso no servidor FTP, demonstrando que o ataque de força bruta foi efetivo.

---

### Cenário 2: Ataque de Força Bruta em Formulário Web (DVWA)

#### Objetivo

Demonstrar como atacantes podem comprometer aplicações web através de ataques automatizados de força bruta em formulários de autenticação, explorando senhas fracas e a ausência de proteções contra tentativas repetidas de login.

#### Fase 1: Reconhecimento da Aplicação Web

Com o servidor Metasploitable ativo, foi identificada a presença do **DVWA (Damn Vulnerable Web Application)** - uma aplicação web intencionalmente vulnerável projetada para treinamento em segurança.

**URL da aplicação identificada:**
```
http://192.168.56.101/dvwa/login.php
```

Para compreender como o formulário de login funciona e preparar o ataque, foi necessário realizar uma análise técnica da página através das ferramentas de desenvolvedor do navegador.

#### Fase 2: Análise do Formulário de Autenticação

Utilizando a função "Inspecionar Elemento" do navegador (F12), foi possível identificar informações cruciais sobre o formulário:

**Informações coletadas:**

1. **Método HTTP:** POST
2. **URL de destino:** `/dvwa/login.php`
3. **Campos do formulário:**
   - `username`: Campo de nome de usuário
   - `password`: Campo de senha
   - `Login`: Botão de submissão

4. **Mensagem de erro:** Ao realizar uma tentativa de login inválida, a aplicação retorna a mensagem:
```
   Login failed
```

> **Importância:** A mensagem "Login failed" será utilizada como **indicador de falha** para o Medusa, permitindo que a ferramenta identifique quando uma tentativa de autenticação não foi bem-sucedida e continue testando outras combinações.

**Estrutura do formulário identificada:**

![Estrutura formulário web DVWA](images/login_dvwa_4.png)
---

#### Fase 3: Criação das Wordlists

Seguindo a mesma metodologia do ataque FTP, foram criadas wordlists personalizadas para o ataque ao formulário web.

**Criação da lista de usuários:**
```bash
echo -e "user\nmsfadmin\nadmin\nroot" > usersDVWA.txt
```

**Conteúdo do arquivo `usersDVWA.txt`:**
```
user
msfadmin
admin
root
```

**Criação da lista de senhas:**
```bash
echo -e "123456\npassword\nqwerty\nmsfadmin" > passwordsDVWA.txt
```

**Conteúdo do arquivo `passwordsDVWA.txt`:**
```
123456
password
qwerty
msfadmin
```

---

#### Fase 4: Execução do Ataque de Força Bruta com Medusa

Com todas as informações necessárias coletadas, foi executado o ataque utilizando o módulo HTTP do Medusa, especificamente projetado para ataques em formulários web.

**Comando executado:**
```bash
medusa -h 192.168.56.101 -U usersDVWA.txt -P passwordsDVWA.txt -M http -m DIR:/dvwa/login.php -m FORM:"username=USER&password=PASS&Login=Login" -m FAIL-LOGIN:"Login failed" -t 6
```

**Explicação detalhada dos parâmetros:**

- **`-h 192.168.56.101`**: Define o endereço IP do host (servidor) alvo
- **`-U usersDVWA.txt`**: Especifica o arquivo contendo a lista de nomes de usuário a serem testados
- **`-P passwordsDVWA.txt`**: Especifica o arquivo contendo a lista de senhas a serem testadas
- **`-M http`**: Define o módulo de ataque para o protocolo HTTP (formulários web)
- **`-m DIR:/dvwa/login.php`**: Especifica o diretório/caminho da página de login na aplicação web
- **`-m FORM:"username=USER&password=PASS&Login=Login"`**: Define a estrutura do formulário POST, onde:
  - `username=USER`: Campo de usuário (USER será substituído por cada entrada da wordlist)
  - `password=PASS`: Campo de senha (PASS será substituído por cada entrada da wordlist)
  - `Login=Login`: Parâmetro do botão de submissão do formulário
- **`-m FAIL-LOGIN:"Login failed"`**: Define a string que indica falha na autenticação (usada para identificar tentativas sem sucesso)
- **`-t 6`**: Estabelece 6 threads paralelas para otimizar a velocidade do ataque

**Como funciona:**

O Medusa realiza requisições HTTP POST para a página de login, enviando combinações de usuário e senha. Para cada resposta recebida, a ferramenta verifica se contém a string "Login failed":
- **Se contém:** A tentativa falhou e o Medusa continua testando
- **Se não contém:** As credenciais são válidas e o ataque foi bem-sucedido

**Resultado do ataque:**

![Saída do Medusa mostrando credenciais encontradas no DVWA](images/found_password_dvwa_5.png)

✅ **Credenciais testadas:**
- **Usuário:** `admin`
- **Senha:** `password`

---

#### Fase 5: Validação do Acesso

Para confirmar o sucesso do ataque, foi realizado um login manual na aplicação DVWA utilizando as credenciais descobertas.

**Passos de validação:**

1. Acessar: `http://192.168.56.101/dvwa/login.php`
2. Inserir as credenciais:
   - **Username:** `admin`
   - **Password:** `password`
3. Clicar em "Login"

**Resultado:**

✅ **Acesso confirmado:** Login realizado com sucesso, redirecionamento para o painel administrativo do DVWA.

---

### Cenário 3: Ataque de Força Bruta e Password Spraying em SMB

#### Objetivo

Demonstrar como atacantes podem comprometer serviços de compartilhamento de arquivos SMB (Server Message Block) através de enumeração de usuários e ataques automatizados de força bruta, explorando configurações inseguras e credenciais fracas em ambientes corporativos.

#### Fase 1: Reconhecimento e Enumeração de Usuários

Diferentemente dos cenários anteriores, o ataque ao protocolo SMB requer uma fase adicional de **enumeração**. Este processo permite identificar usuários válidos, compartilhamentos disponíveis, políticas de senha e outras informações valiosas sobre o sistema alvo antes de iniciar o ataque propriamente dito.

Para realizar esta enumeração, foi utilizada a ferramenta **enum4linux**, especializada em extrair informações de sistemas Windows e Samba através do protocolo SMB.

**Comando executado:**
```bash
enum4linux -a 192.168.56.101 | tee enum4_output.txt
```

**Explicação detalhada dos parâmetros:**

- **`enum4linux`**: Ferramenta de enumeração para sistemas SMB/CIFS
- **`-a`**: Executa **todas** as opções de enumeração disponíveis, incluindo:
  - Enumeração de usuários do sistema
  - Enumeração de grupos e membros
  - Listagem de compartilhamentos de rede
  - Informações sobre políticas de senha
  - Informações do sistema operacional
  - Detalhes do domínio/workgroup
- **`192.168.56.101`**: Endereço IP do alvo
- **`| tee enum4_output.txt`**: Operador pipe que:
  - Exibe a saída no terminal em tempo real
  - Simultaneamente salva todo o output no arquivo `enum4_output.txt` para análise posterior

**Informações relevantes obtidas:**

Após a execução do comando, foram identificados:

✅ **Usuários enumerados:**
- `user`
- `msfadmin`
- `service`
- `root`
- Outros usuários do sistema

✅ **Compartilhamentos disponíveis:**
- `tmp` - Diretório temporário
- `IPC$` - Comunicação entre processos
- Outros compartilhamentos

✅ **Políticas de segurança:**
- Sem bloqueio de conta configurado
- Sem complexidade de senha exigida
- Sem expiração de senha

> **Importância da enumeração:** Esta fase é crucial pois fornece uma lista de usuários válidos, reduzindo significativamente o número de tentativas necessárias e aumentando a taxa de sucesso do ataque. Em vez de testar usuários aleatórios, o atacante foca apenas em contas que realmente existem no sistema.

---

#### Fase 2: Criação das Wordlists Direcionadas

Com base nas informações coletadas durante a enumeração, foram criadas wordlists mais específicas, priorizando os usuários identificados no sistema.

**Criação da lista de usuários:**
```bash
echo -e 'user\nmsfadmin\nservice' > usersSMB.txt
```

**Conteúdo do arquivo `usersSMB.txt`:**
```
user
msfadmin
service
```

> **Nota:** Diferente dos cenários anteriores, esta wordlist foi construída com base na enumeração real, contendo apenas usuários confirmados no sistema alvo.

**Criação da lista de senhas:**
```bash
echo -e 'password\n123456\nwelcome123\nmsfadmin' > passwordsSMB.txt
```

**Conteúdo do arquivo `passwordsSMB.txt`:**
```
password
123456
welcome123
msfadmin
```

---

#### Fase 3: Execução do Ataque de Força Bruta no SMB

Com as wordlists preparadas e os usuários enumerados, foi executado o ataque utilizando o módulo **smbnt** do Medusa, projetado especificamente para o protocolo SMB/CIFS.

**Comando executado:**
```bash
medusa -h 192.168.56.101 -U usersSMB.txt -P passwordsSMB.txt -M smbnt -t 2 -T 50
```

**Explicação detalhada dos parâmetros:**

- **`-h 192.168.56.101`**: Define o endereço IP do host (servidor) alvo
- **`-U usersSMB.txt`**: Especifica o arquivo contendo a lista de usuários enumerados
- **`-P passwordsSMB.txt`**: Especifica o arquivo contendo a lista de senhas a serem testadas
- **`-M smbnt`**: Define o módulo de ataque para o protocolo SMB/CIFS (Server Message Block)
- **`-t 2`**: Estabelece **2 threads paralelas** (conexões simultâneas)
  - Valor reduzido para evitar sobrecarga no servidor alvo
  - Reduz chances de detecção por sistemas de monitoramento
  - Recomendado para serviços SMB que podem ser sensíveis a múltiplas conexões
- **`-T 50`**: Define o **timeout** de 50 segundos para cada tentativa de conexão
  - Tempo de espera máximo para cada tentativa antes de considerar falha
  - Importante para serviços SMB que podem ter latência maior

**Como funciona:**

O Medusa realiza tentativas de autenticação no serviço SMB combinando cada usuário com cada senha. O protocolo SMB utiliza autenticação NTLM, e o módulo smbnt do Medusa simula esse processo para testar as credenciais.

**Diferença estratégica:**
- **Threads reduzidas (-t 2)**: Ao contrário do FTP que utilizou 6 threads, o SMB é mais sensível e pode bloquear conexões excessivas
- **Timeout maior (-T 50)**: O SMB pode ser mais lento na resposta de autenticação comparado a outros protocolos

**Resultado do ataque:**

![Saída do Medusa mostrando credenciais encontradas no SMB](images/found_password_smb_6.png)

✅ **Credenciais comprometidas:**
- **Usuário:** `msfadmin`
- **Senha:** `msfadmin`

---

#### Fase 4: Validação do Acesso ao Serviço SMB

Para confirmar o sucesso do ataque e verificar os recursos acessíveis, foi utilizada a ferramenta **smbclient** para estabelecer uma conexão legítima com o servidor.

**Comando executado:**
```bash
smbclient -L //192.168.56.101 -U msfadmin
```

**Explicação dos parâmetros:**

- **`smbclient`**: Cliente de linha de comando para acessar recursos SMB/CIFS
- **`-L`**: Lista todos os compartilhamentos disponíveis no servidor (List shares)
- **`//192.168.56.101`**: Endereço do servidor SMB no formato UNC (Universal Naming Convention)
- **`-U msfadmin`**: Especifica o nome de usuário para autenticação

Após executar o comando, foi solicitada a senha:
```
Enter msfadmin's password: msfadmin
```

**Resultado:**

![Acesso bem-sucedido ao servidor SMB e listagem de compartilhamentos](images/connect_smb_7.png)

✅ **Acesso confirmado:** Conexão estabelecida com sucesso, listando os seguintes compartilhamentos:
---

## 🛡️ Medidas de Mitigação

### Recomendações Gerais

#### 1. **Políticas de Senha Robustas**

- **Descrição:** Estabelecer requisitos mínimos para senhas fortes em todos os sistemas.
- **Implementação:** Mínimo 12 caracteres, combinação de maiúsculas, minúsculas, números e símbolos.

#### 2. **Limitação de Tentativas (Rate Limiting)**

- **Descrição:** Limitar tentativas de autenticação em período determinado.
- **Implementação:** Bloqueio temporário após 3-5 tentativas falhas com tempo crescente. Utilizar Fail2Ban para automação.

#### 3. **Autenticação Multifator (MFA/2FA)**

- **Descrição:** Adicionar segunda camada de autenticação além da senha.
- **Implementação:** TOTP via apps (Google Authenticator), tokens hardware (YubiKey), obrigatório para contas administrativas.

#### 4. **Monitoramento e Logging**

- **Descrição:** Registrar e analisar tentativas de autenticação.
- **Implementação:** Logs de todas as tentativas, alertas para múltiplas falhas, retenção mínima de 90 dias.

#### 5. **Desabilitar Enumeração de Usuários**

- **Descrição:** Impedir identificação de usuários válidos.
- **Implementação:** Mensagens genéricas de erro, desabilitar listagem de usuários, bloquear ferramentas de enumeração.

#### 6. **Segmentação de Rede**

- **Descrição:** Limitar acesso a serviços críticos.
- **Implementação:** Firewall com whitelist de IPs, VPN para acesso remoto, VLANs para segregação.

---

### Medidas Específicas por Serviço

#### FTP

**Principais vulnerabilidades:** Credenciais fracas, transmissão em texto plano, sem limitação de tentativas.

**Recomendações:**
1. **Migrar para SFTP/FTPS** - Criptografar todas as transferências 
2. **Configurar Fail2Ban** - Bloquear após 3 tentativas falhas 
3. **Restringir por IP** - Whitelist de IPs autorizados 
4. **Desabilitar root/admin** - Criar usuários específicos para FTP 
5. **Implementar chroot** - Isolar usuários em diretórios 

---

#### Aplicações Web (DVWA)

**Principais vulnerabilidades:** Credenciais fracas, ausência de CAPTCHA, mensagens de erro reveladoras.

**Recomendações:**
1. **Implementar CAPTCHA** - reCAPTCHA após 2-3 tentativas 
2. **Rate Limiting** - Limitar 5 tentativas por 15 minutos 
3. **WAF** - ModSecurity, CloudFlare ou AWS WAF 
4. **Mensagens genéricas** - "Credenciais inválidas" apenas 
5. **Bloqueio de conta** - Após 5 tentativas com recuperação via email 
6. **Headers de segurança** - HSTS, X-Frame-Options, forçar HTTPS 

---

### Documentações Oficiais

- [Kali Linux – Site Oficial](https://www.kali.org/)
- [DVWA – Damn Vulnerable Web Application](https://github.com/digininja/DVWA)
- [Medusa – Documentação](http://foofus.net/goons/jmk/medusa/medusa.html)
- [Nmap – Manual Oficial](https://nmap.org/book/man.html)

## ⚠️ Aviso Legal

Este projeto foi desenvolvido **exclusivamente para fins educacionais** em ambiente controlado. 

**IMPORTANTE:**
- Todos os testes foram realizados em máquinas virtuais isoladas
- Nunca utilize estas técnicas em sistemas sem autorização explícita
- O uso indevido destas técnicas é **ilegal** e pode resultar em consequências criminais
- Este material não deve ser usado para atividades maliciosas

---

## 👤 Autor

**Phablo Loureiro Alves**
- LinkedIn: https://www.linkedin.com/in/phablo-loureiro-alves/

