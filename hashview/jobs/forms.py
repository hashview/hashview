"""Forms Page to manage Jobs"""
from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField, SelectField, TextAreaField, FileField
from wtforms.validators import DataRequired, ValidationError
from hashview.models import Jobs


class JobsForm(FlaskForm):
    """Class representing an Jobs Forms"""

	name = StringField('Job Name', validators=[DataRequired()])
	priority = SelectField('Job Priority', choices=[('5', '5 - highest'),
													('4', '4 - higher'),
													('3', '3 - normal'),
													('2', '2 - lower'),
													('1', '1 - lowest')], default=3, validators=[DataRequired()])
	customer_id = StringField('Customer ID (unused)', validators=[DataRequired()])
	customer_name = StringField('Customer Name (unused)')
	submit = SubmitField('Next')

	def validate_job(self, name):
		job = Jobs.query.filter_by(name = name.data).first()
		if job:
			raise ValidationError('That job name is taken. Please choose a different one.')

class JobsNewHashFileForm(FlaskForm):
    """Class representing an Jobs New Hashfile Form"""

    name = StringField('Hashfile Name') # While required we may dynamically create this based on file upload
    file_type = SelectField('Hash File Format', choices=[('', '--SELECT--'),
													('pwdump', 'pwdump()'), 
													('NetNTLM', 'NetNTLMv1, NetNTLMv1+ESS or NetNTLMv2'), 
													('kerberos', 'Kerberos'),
													('shadow', 'Linux / Unix Shadow File'),
													('user_hash', '$user:$hash'),
													('hash_only', '$hash')], validators=[DataRequired()])
													
    hash_type = SelectField('Hash Type', choices=[  ('', '------SELECT------'),
    						    					('', 'O P E R A T I N G   S Y S T E M'),
													('0', '(0) MD5'),
													('22', '(22) Juniper NetScreen ScreenOS'),													
						    							('122', '(122) Mac OSX (from 10.4 to 10.7)'),
													('500', '(500) Cisco-IOS $1$'),
													('500', '(500) md5crypt / Unix $1$'),
						  							('1000', '(1000) NTLM'),
						    							('1100', '(1100) MSCache / DomainCachedCredentials'),
													('1500', '(1500) descrypt / DES Unix'),	
													('1800', '(1800) sha512crypt / Unix $6$'),																									
						    							('2100', '(2100) MSCache 2 / DCC2'),													
													('2400', '(2400) Cisco-PIX'),
													('2410', '(2410) Cisco-ASA'),
													('3200', '(3200) bcrypt / Blowfish Unix $2*$'),
													('5700', '(5700) Cisco-IOS type 4 (SHA256)'),
													('7000', '(7000) FortiGate (FortiOS)'),
						    							('7100', '(7100) Mac OSX 10.8+ ($ml$)'),
													('8100', '(8100) Citrix NetScaler (SHA1)'),
													('9900', '(9900) Radmin2'),													
													('22200', '(22200) Citrix NetScaler (SHA512)'),

													('', ''), # Spacer for better visibility					    
													('', 'R A W   &  S A L T E D'),
													('0', '(0) MD5 (raw)'),
													('10', '(10) MD5 + salt ($pass.$salt)'),
													('20', '(20) MD5 + salt ($salt.$pass)'),	
													('100', '(100) SHA-1 (raw)'),
													('110', '(110) SHA-1 + salt ($pass.$salt)'),
													('120', '(120) SHA-1 + salt ($salt.$pass)'),																									
													('900', '(900) MD4'),
													('1300', '(1300) SHA-224'),
													('1400' ,'(1400) SHA-256  (raw)'),
													('1420', '(1420) SHA-256 + salt ($salt.$pass)'),
													('1700', '(1700) SHA-512'),
													('1710', '(1710) SHA-512 + salt ($pass.$salt)'),
													('1720', '(1720) SHA-512 + salt ($salt.$pass)'),
													('3800', '(3800) MD5 + salt ($salt.$pass.$salt)'),
													('6000', '(6000) RIPEMD-160'),
													('10100', '(10100) SipHash'),
													('14000', '(14000) DES (PT = $salt, key = $pass)'),
													('1410', '(1410) SHA-256 + salt ($pass.$salt)'),
													('18000', '(18000) Keccak-512'),

													('', ''), # Spacer for better visibility
													('', 'F O R U M   ,   C M S   ,   F R A M E W O R K'),
													('11', '(11) Joomla < v2.5.18'),
													('21', '(21) osCommerce, xt:Commerce'),
													('121', '(121) Simple Machines Forum > v1.1'),
													('124', '(124) Django (SHA1)'),													
													('400', '(400) Wordpress $P$'),
													('400', '(400) Joomla < v3.2 $P$'),
													('400', '(400) phpBB < v3.1 $H$'),
													('2611', '(2611) vBulletin < v3.8.5'),	
													('2711', '(2711) vBulletin >= v3.8.5'),	
													('2811', '(2811) IPB2+, MyBB v1.2+'),													
													('3200', '(3200) Wordpress $2*$'),
													('3200', '(3200) Joomla >= v3.2 $2y$'),
													('3200', '(3200) phpBB >= v3.1 $2y$'),
													('3711', '(3711) MediaWiki $B$'),
													('4522', '(4522) PunBB'),		
													('7900', '(7900) Drupal 7'),																								
													('10000', '(10000) Django (PBKDF2-SHA256)'),
													('11000', '(11000) PrestaShop'),
													('13900', '(13900) OpenCart'),

													('', ''), # Spacer for better visibility
													('', 'D A T A B A S E'),
													('12', '(12) PostgreSQL'),
													('112', '(112) Oracle 11+'),	
													('131', '(131) Microsoft MSSQL (all versions)'),												
													('300', '(300) MySQL (all versions)'),
													('1731', '(1731) MSSQL (2012, 2014)'),
													
													('', ''), # Spacer for better visibility
													('', 'M O B I L E'),
													('5800', '(5800) Samsung Android Password/PIN'),
													('13800', '(13800) Windows Phone 8+ Password/PIN'),
													
													('', ''), # Spacer for better visibility
													('', 'N E T W O R K   P R O T O C O L'),
													('23', '(23) Skype'),	
													('101', '(101) LDAP SHA-1 (Base64), nsldap {SHA}'),
													('111', '(111) LDAP SSHA-1 (Base64), nsldaps {SSHA}'),		
													('1411', '(1411) LDAP SSHA-256 (Base64) {SSHA256}'),
													('1600', '(1600) Apache $apr1$ MD5, md5apr1'),													
													('1711', '(1711) LDAP SSHA-512 (Base64) {SSHA512}'),
													('4800', '(4800) iSCSI CHAP auth, MD5(CHAP) (hash:salt:id)'),
													('5300', '(5300) IKE-PSK MD5'),
													('5400', '(5400) IKE-PSK SHA1'),													
													('7300', '(7300) IPMI2 RAKP HMAC-SHA1'),													
													('8300', '(8300) DNSSEC (NSEC3)'),
													('16100', '(16100) TACACS+'),
													('16500', '(16500) JWT (JSON Web Token)'),													
													('16800', '(16800) WPA PMKID (mode 16800)'),
													('22000', '(22000) WPA PMKID+EAPOL (WPA*01/2)'),

													('', ''), # Spacer for better visibility
													('', 'A R C H I V E'),
													('11600', '(11600) 7-zip ($7z$)'),													
													('12500', '(12500) RAR3-hp (only $RAR3$*0)'),
													('13000', '(13000) RAR5'),
													('13200', '(13200) AxCrypt 1'),
													('23500', '(23500) AxCrypt 2 AES-128'),

													('', ''), # Spacer for better visibility
						    						('', 'G E N E R I C   K D F'),
													('10000', '(10000) PBKDF2-SHA256'),													
													('10900', '(10900) PBKDF2-HMAC-SHA256'),													
													('11900', '(11900) PBKDF2-HMAC-MD5'),
													('12000', '(12000) PBKDF2-HMAC-SHA1'),
													('12100', '(12100) PBKDF2-HMAC-SHA512'),

													('', ''), # Spacer for better visibility
													('', 'P A S S W O R D   M A N A G E R'),
													('6800', '(6800) LastPass / LastPass sniffed'),													
													('13400', '(13400) Keepass (all versions)'),	
													('15500', '(15500) JKS Java Key Store SHA1 ($jksprivk$)'),																									
													('23100', '(23100) Apple Keychain ($keychain$)'),
													('66001', '(66001) Password, agilekeychain'),

													('', ''), # Spacer for better visibility
													('', 'C Y R P T O C U R R E N C Y   W A L L E T'),
													('11300', '(11300) Bitcoin wallet ($bitcoin$)'),
													('11300', '(11300) Litecoin wallet'),													
													('15600', '(15600) Ethereum wallet ($ethereum$p/w)'),
													('16600', '(16600) Electrum wallet ($electrum$)'),
													('26600', '(26600) Metamask wallet ($metamask$)'),
													('22500', '(22500) MultiBit Classic .key ($multibit$)'),

													('', ''), # Spacer for better visibility
													('', 'F U L L - D I S K   E N C R Y P T I O N'),
													('18300', '(18300) Apple File System (APFS) $fvde$'),
													('16700', '(16700) FileVault 2 $fvde$'),

													('', ''), # Spacer for better visibility
													('', 'P R I V A T E   K E Y S'),
													('22921', '(22921) RSA/DSA/EC/OpenSSH Private Keys ($sshng$)'),

													('', ''), # Spacer for better visibility
													('', 'O N E - T I M E   P A S S W O R D S'),
													('18100', '(18100) Time-based OTP (HMAC-SHA1)'),

													('', ''), # Spacer for better visibility
													('', 'D O C U M E N T S'),
													('16200', '(16200) Apple Secure Notes $ASN$'),
													('23300', '(23300) Apple iWork $iwork$'),
						  							('9400', '(9400) MS Office 2007'),
						  							('9500', '(9500) MS Office 2010'),
						  							('9600', '(9600) MS Office 2013'),

													('', ''), # Spacer for better visibility
													('', 'E N T E R P R I S E   S O F T W A R E'),
													('133', '(133) Oracle PeopleSoft'),
													('16900', '(16900) Ansible Vault'),
													('15000', '(15000) FileZilla Server (hash:salt)'),])

    shadow_hash_type = SelectField('Hash Type', choices=[  ('', '------SELECT------'),
													('500', '(500) md5crypt / Unix $1$'),
													('1500', '(1500) descrypt / DES Unix'),	
													('1800', '(1800) sha512crypt / Unix $6$'),																									
													('3200', '(3200) bcrypt / Blowfish Unix $2*$')])

    pwdump_hash_type = SelectField('Hash Type', choices=[  ('', '------SELECT------'),
													('1000', '(1000) NTLM')])

    netntlm_hash_type = SelectField('Hash Type', choices=[  ('', '------SELECT------'),												
													('5500', '(5500) NetNTLM v1 / NetNTLMv1+ESS'),
													('5600', '(5600) NetNTLM v2'),
													('27000', '(27000) NetNTLMv1 / NetNTLMv1+ESS (NT)'),
													('27100', '(27100) NetNTLMv2 (NT)')])

    kerberos_hash_type = SelectField('Hash Type', choices=[  ('', '------SELECT------'),			
													('7500', '(7500) Kerberos 5, etype 23, AS-REQ Pre-Auth ($krb5pa)'),
													('13100', '(13100) Kerberos 5, etype 23, TGS-REP ($krb5tgs)'),
													('18200', '(18200) Kerberos 5, etype 23, AS-REP ($krb5asrep)'),
													('19600', '(19600) Kerberos 5 TGS-REP etype 17 (AES128-CTS-HMAC-SHA1-96)'),
													('19700', '(19700) Kerberos 5 TGS-REP etype 18 (AES256-CTS-HMAC-SHA1-96)'),
													('19800', '(19800) Kerberos 5, etype 17, Pre-Auth'),
													('19900', '(19900) Kerberos 5, etype 18, Pre-Auth')])													

    hashfilehashes = TextAreaField('Hashes')
    hashfile = FileField('Upload Hashfile')
    submit = SubmitField('Next')

class JobsNotificationsForm(FlaskForm):
	"""Class representing Job Notification Form"""    

    job_completion = SelectField('Notify when Job completes', choices=[('none', 'No'),
													                    ('email', 'Send Email'),
													                    ('push', 'Send Push Notification')], validators=[DataRequired()])
    hash_completion = SelectField('Notify when specific hashes crack', choices=[('none', 'No'),
													                    ('email', 'Send Email'),
													                    ('push', 'Send Push Notification')], validators=[DataRequired()])
    submit = SubmitField('Next')

class JobSummaryForm(FlaskForm):
    """Class representing an Jobs Summary"""

    submit = SubmitField('Complete')
