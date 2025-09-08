<div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px;">
    <div style="background-color: #FF9800; color: white; padding: 20px; text-align: center; border-radius: 5px;">
        <h1 style="margin: 0;">密码重置</h1>
    </div>
    
    <div style="padding: 20px; background-color: #f9f9f9; border-radius: 5px; margin-top: 20px;">
        <p style="font-size: 16px;">亲爱的用户：</p>
        
        <p style="font-size: 16px; line-height: 1.6;">
            我们收到了您的密码重置请求。请使用以下验证码来重置您的密码：
        </p>
    
        <div style="background-color: #fff; padding: 20px; border-radius: 8px; text-align: center; margin: 25px 0; border: 2px solid #FF9800; box-shadow: 0 2px 4px rgba(0,0,0,0.1);">
            <div style="font-size: 32px; font-weight: bold; color: #000; letter-spacing: 8px; font-family: 'Courier New', monospace;">
                {{.code}}
            </div>
        </div>

        <p style="font-size: 14px; color: #666; margin-top: 30px;">
            该验证码有效期为10分钟，请勿向他人透露！
            如果您没有请求重置密码，请忽略此邮件，您的密码将保持不变。
        </p>
    </div>
    
    <div style="margin-top: 20px; padding: 20px; border-top: 1px solid #eee; color: #666; font-size: 14px;">
        <p>此致</p>
        <p>您的团队</p>
    </div>
</div>
