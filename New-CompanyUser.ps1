#requires -version 3
<#
.Synopsis
   Cкрипт для автоматизации заведения нового пользователя

.DESCRIPTION
   Скрипт выполняет следующие задачи:
    1. Спрашивает у администратора данные сотрудника: Имя, Фамилию, Логин, Отдел
    2. Создаёт нового пользователя в Active Directory
    3. Добавляет созданного пользователя в security группу Отдела
    3. Заводит почтовый ящик в Exchange
    4. Добавляет почтовый адрес в группу рассылки Отдела

.EXAMPLE
   New-CompanyUser -SamAccountName 'IIvanov' -DisplayName 'Иван Иванов' -Department 'Маркетинг'

.EXAMPLE
   New-CompanyUser 'IIvanov' 'Иван Иванов' 'Маркетинг'

.INPUTS
   Входные данные в этот командлет (при наличии)
.OUTPUTS
   Выходные данные из этого командлета (при наличии)
.NOTES
   Общие примечания
#>
function New-CompanyUser {
    [CmdletBinding()]
    Param(
        # Логин
        [Parameter(Mandatory=$true, 
                   ValueFromPipeline=$true,
                   Position=0)]
        [ValidateNotNullOrEmpty()]
        [Alias("Name", "Login")]
        [string]$SamAccountName,

        # Имя Фамилия
        [Parameter(Mandatory=$true, 
                   ValueFromPipeline=$true, 
                   Position=1)]
        [ValidateNotNullOrEmpty()]
        [ValidateScript({
            if ($_ -cnotmatch '^[А-ЯA-Z][а-яa-z]*.*\s[А-ЯA-Z][а-яa-z]*.*$') {
                throw "Введите имя и фамилию в формате 'Имя Фамилия'"
            }
            else {$true}
        })]
        [string]$DisplayName,

        # Отдел
        ## Возможно стоит добавить ValidateSet со списком отделов, если их не сильно много
        [Parameter(Mandatory=$true, 
                   ValueFromPipeline=$true, 
                   Position=2)]
        [ValidateNotNullOrEmpty()]
        [Alias("Dept")]
        [string]$Department,

        # Почтовый домен
        [ValidateNotNullOrEmpty()]
        [string]$MailDomain = 'company.com',

        # Чтобы не писать каждый раз -ErrorAction Stop
        ## Переопределяем значение по умолчанию. Будет переопределено при использовании -ErrorAction
        <#
        Valid values: 
        Stop: Displays the error message and stops executing.
        Inquire: Displays the error message and asks you whether you want to continue.
        Continue: Displays the error message and continues (Default) executing.
        Suspend: Automatically suspends a workflow job to allow for further investigation. After investigation, the workflow can be resumed.
        SilentlyContinue: No effect. The error message is not displayed and execution continues without interruption.
        NOTE: The Ignore value of the ErrorAction common parameter is not a valid value of the $ErrorActionPreference variable. 
        The Ignore value is intended for per-command use, not for use as saved preference.
        #>
        [ValidateSet('Stop','Inquire','Continue','Suspend','SilentlyContinue')]
        $ErrorActionPreference = 'Stop'
    )

    Begin
    {
        try {
            # Импортируем модель AD
            Import-Module ActiveDirectory
            # Создадим сесcию Exchange
            $ExchangeSession = New-PSSession -ConfigurationName Microsoft.Exchange -ConnectionUri http://mail.company.com/PowerShell/ -Authentication Kerberos
            Import-PSSession $ExchangeSession
        }
        catch {
            Write-Error -Exception $_.Exception -Message $_.Exception.Message
            break
        }
    }
    Process
    {
        try {
            # Проверим, нет ли уже такого юзера
            if (Get-ADUser -Identity $SamAccountName) {
                throw "Пользователь с логином [$SamAccountName] уже существует!"
            }
            elseif (Get-Mailbox -Identity "$SamAccountName@$MailDomain") {
                throw "Почтовый ящик [$SamAccountName@$MailDomain] уже существует!"
            }
            elseif (Get-ADUser * -Filter "DisplayName -eq '$DisplayName'") {
                Write-Warning "Пользователь с именем [$DisplayName] уже существует!"
                if ( (Read-Host "Продолжить создание пользователя с таким именем? (y/n)") -notmatch '^y$|^yes$') {
                    Write-Host -f Yellow "Отменено пользователем."
                    break
                }
            }

            # Создадим временный пароль
            $TempPassword = New-RandomPassword
            Write-Host -f Yellow "Пользователю будет присвоен временный пароль: [$TempPassword]"

            # Создадим юзера
            ## Избавляемся от паста-кода через Splatting!
            $MailboxParams = @{
                UserPrincipalName = "$SamAccountName@$MailDomain"
                Alias = $SamAccountName
                FirstName = $DisplayName.Split()[0]
                LastName = $DisplayName.Split()[1]
                DisplayName = $DisplayName
                Name = $DisplayName.Split() -join ''
                Password = ConvertTo-SecureString -String $TempPassword -AsPlainText -Force
                Database = "Default"
                OrganizationalUnit = 'Users'
                ResetPasswordOnNextLogon = $true
            }

            # Нет необходимости создавать отдельно юзера в AD - New-Mailbox заводит сразу и в AD и ящик к нему в Exchange
            # https://technet.microsoft.com/en-us/library/aa997663(v=exchg.160).aspx (см. Example 1)
            New-Mailbox @MailboxParams

            # Ждём, пока AD отдуплится. Считаем, что отдупляется быстро.
            # Если с отдуплением проблемы, то можно воспользоваться советом с технета:
            # https://social.technet.microsoft.com/Forums/windowsserver/en-US/3b297088-b774-4e19-bdba-7857f7b610a1/powershell-new-user-script-delaysynchronisation-problem?forum=winserverpowershell
            Start-Sleep -Seconds 10

            # Предположим, что группа в AD и Exchange Соответствуют названию отдела.
            # В противном случае можно сделать сопоставление групп отдулам в начале скрипта.
            # В идеале бы нужно включить группу AD в DistributionGroup в Exchange и добавлять только в одну группу AD.
            Add-DistributionGroupMember -Identity $Department -Member $MailboxParams.UserPrincipalName
            Add-ADGroupMember -Identity $Department -Members (Get-ADUser $SamAccountName)
        }
        catch {
            Write-Error -Exception $_.Exception -Message $_.Exception.Message
            break
        }
    }
    End
    {
        Remove-PSSession $ExchangeSession
    }
}

# Генерирует пароль заданной длины. Учитывает требования по сложности Aa1
## TODO: исключить похожие (O0 Il1 :; итп.)
function New-RandomPassword {
    param (
        [int]$Lenght = 8
    )
    #$UpperLetters = 65..90 | %{[char]$_}
    #$LowerLetters = 97..122 | %{[char]$_}
    #$Symbols = 33..47 + 59..64 + 91..94 | %{[char]$_}
    #$Digits = 48..57 | %{[char]$_}
    $RandomSeed = 33..94 + 97..122

    while ($Password -notmatch "^(?=.*\d)(?=.*[a-z])(?=.*[A-Z]).{$Lenght}") {
        $Password = (Get-Random -InputObject $RandomSeed -Count $Lenght | ForEach-Object {
            [char]$_
        }) -join ''
    }

    return $Password
}

New-CompanyUser