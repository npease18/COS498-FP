import nodemailer from 'nodemailer';
import dotenv from 'dotenv';

dotenv.config({path: './email/.env'});

class EmailManager {
    constructor() {
        this.transporter = nodemailer.createTransport({
            host: process.env.EMAIL_HOST,
            port: process.env.EMAIL_PORT,
            secure: process.env.EMAIL_SECURE === 'true',
            auth: {
                user: process.env.EMAIL_SENDER_EMAIL,
                pass: process.env.EMAIL_ACCOUNT_PASSWORD
            }
        })
    }

    async sendEmail (to, subject, emailContent) {
        this.transporter.sendMail({
            from: `"Comment Corner" <${process.env.EMAIL_SENDER_EMAIL}>`,
            to: to,
            subject: subject,
            html: emailContent,
        }).then(info => {
            console.log("Test email sent: " + info.messageId);
            return true;
        }).catch(err => {
            console.error("Error sending test email: ", err);
            return false;
        });
        return { success: true, messageId: 'not-configured' };
    }
}

export default EmailManager;