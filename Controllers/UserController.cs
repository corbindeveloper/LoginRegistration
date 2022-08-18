using System.Diagnostics;
using Microsoft.AspNetCore.Mvc;
using LoginRegistration.Models;
using Microsoft.AspNetCore.Identity;

namespace EntityFrameworkLecture.Controllers;

public class UserController : Controller
{ 
    // _context is just a variable name -- It can be called anything such as db, or DATABASE
        private LoginRegistrationContext db;

    // here we can "inject" our context service into the constructor
    public UserController(LoginRegistrationContext context)
    {
        db = context;
    }


    // ===========================================================
    // INDEX // SIGN UP
    [HttpGet("/")]
    [HttpGet("/register")]
    public IActionResult Register()
    {
        return View("Register");
    }




    // ===========================================================
    // REGISTER
    [HttpPost("/register/user")]
    public IActionResult RegisterUser(User newUser)
    {
        if (ModelState.IsValid)
        {
            if (db.Users.Any(user => user.Email == newUser.Email))
            {
                ModelState.AddModelError("Email", "Is already in use");
            }
        }


        if (ModelState.IsValid == false)
        {
            return Register();
        }

        // Hash Passwords
        PasswordHasher<User> hashBrowns = new PasswordHasher<User>();
        newUser.Password = hashBrowns.HashPassword(newUser, newUser.Password);

        db.Users.Add(newUser);
        db.SaveChanges();

        HttpContext.Session.SetInt32("UUID", newUser.UserId);
        HttpContext.Session.SetString("Name", newUser.FullName());

        return RedirectToAction("Dashboard", "User"); // To the all method in the post controller
    }

    // ===========================================================
    // LOGIN
    [HttpGet("/login/user")]
    public IActionResult LoginPage()
    {
        return View("Login");
    }


    // ===========================================================
    // LOGIN
    [HttpPost("/login")]
    public IActionResult Login(LoginUser loginUser)
    {
        // Verify data is valid
        if (ModelState.IsValid == false)
        {
            return Register();
        }

        // Make sure email exist within db
        User? dbUser = db.Users.FirstOrDefault(user => user.Email == loginUser.LoginEmail);

        if (dbUser == null)
        {
            ModelState.AddModelError("LoginEmail", "not found");
            return Register();
        }

        // Compare hashed passwords
        PasswordHasher<LoginUser> hashBrowns = new PasswordHasher<LoginUser>();
        PasswordVerificationResult pwCompareResult = hashBrowns.VerifyHashedPassword(loginUser, dbUser.Password, loginUser.LoginPassword);
        
        if (pwCompareResult == 0)
        {
            ModelState.AddModelError("LoginPassword", "is not correct");
            return Register();
        }

        // Log the user in
        HttpContext.Session.SetInt32("UUID", dbUser.UserId);
        HttpContext.Session.SetString("Name", dbUser.FullName());
        
        return RedirectToAction("Dashboard", "User");

    }


    // ===========================================================
    // LOGOUT
    [HttpPost("/logout")]
    public IActionResult Logout()
    {
        HttpContext.Session.Clear();
        return RedirectToAction("Index");
    }

    // ===========================================================
    // LOGOUT
    [HttpGet("/dashboard")]
    public IActionResult Dashboard()
    {
        return View("Dashboard");
    }

}