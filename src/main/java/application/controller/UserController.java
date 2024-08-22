package application.controller;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;


@Controller
public class UserController {

    // Unprotected endpoint
    @GetMapping("/landing")
    @ResponseBody
    public String getLandingPage() {
        return "Welcome to the landing page!";
    }

    // Login page endpoint
    @GetMapping("/login")
    public String getLoginPage() {
        return "login";  // This will return the "login.html" Thymeleaf template
    }

    // Protected endpoint
    @GetMapping("/user")
    @ResponseBody
    public String getUserPage() {
        // Retrieve the Authentication object for the current user
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();

        // Get the username from the Authentication object
        String username = authentication.getName();

        // Return a personalized welcome message
        return "Welcome, " + username + ", to the user page!";
    }
    // Protected endpoint
    @GetMapping("/admin")
    @ResponseBody
    public String getAdminPage() {
        // Retrieve the Authentication object for the current user
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();

        // Get the username from the Authentication object
        String username = authentication.getName();

        // Return a personalized welcome message
        return "Welcome, " + username + ", to the Admin page!";
    }

    @GetMapping("/403")
    public String errorPage() {
        return "403";
    }


}
