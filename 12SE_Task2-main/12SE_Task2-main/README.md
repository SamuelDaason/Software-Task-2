# VIP (Vulnerability Issues Pizza) 🍕

Welcome to the VIP Pizza Shop, a deliberately vulnerable web application designed for learning web security concepts! This application is intentionally built with security flaws to help students practice identifying and understanding common web vulnerabilities.

## 🎯 Purpose

This web application simulates a pizza ordering system where users can:
- Register and login
- Browse available pizzas
- Add items to cart
- Place orders
- Access admin features (if you have permissions)

Your mission is to find security vulnerabilities in this application. Think like a hacker - what could go wrong?

## 🚀 Getting Started

1. Install dependencies:
```bash
pip install -r requirements.txt
```

2. Run the application:
```bash
python app.py
```

3. Visit http://localhost:5000 in your browser

## 🔍 What to Look For

As you explore the application, consider these questions:

1. **User Authentication**
   - How secure is the login system?
   - What happens if you provide unexpected input?
   - Can you access areas you shouldn't?

2. **Data Storage**
   - How is sensitive information stored?
   - Can you find any interesting files?
   - What information might be exposed?

3. **Input Handling**
   - What happens when you submit unusual data?
   - Are there any error messages that reveal too much?
   - Can you manipulate the application's behavior?

4. **Admin Features**
   - How are admin privileges determined?
   - Can regular users access admin features?
   - What special functions are available to admins?

## 💡 Tips

1. Use browser developer tools
2. Pay attention to URLs and parameters
3. Watch for interesting error messages
4. Try unexpected inputs
5. Look for hidden features or comments
6. Check how data is stored and transmitted

## ⚠️ Important Notes

1. This application is intentionally vulnerable - DO NOT use it in production!
2. Practice ethical hacking - only test on this application
3. Document your findings
4. Think about how each vulnerability could be fixed

## 🎓 Learning Resources

To help with your security testing, consider learning about:
- Web application architecture
- Common web vulnerabilities (OWASP Top 10)
- HTTP methods and status codes
- Database queries and injection
- Authentication and session management
- Browser developer tools

## 🏆 Challenge

Can you find and document all the vulnerabilities in this application? Keep track of:
- What vulnerabilities you find
- How you discovered them
- What could be the impact
- How they could be fixed

Good luck, and happy hunting! 🕵️‍♂️

## 📝 Note

Remember: The goal is to learn about web security. Use these skills responsibly and only on systems you have permission to test.
