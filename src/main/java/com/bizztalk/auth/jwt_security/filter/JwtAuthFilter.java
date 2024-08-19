package com.bizztalk.auth.jwt_security.filter;

import com.bizztalk.auth.jwt_security.service.JwtService;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.NonNull;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.lang.reflect.Array;
import java.util.ArrayList;
import java.util.List;
import java.util.stream.Collectors;

@Component
@RequiredArgsConstructor
@Slf4j
public class JwtAuthFilter extends OncePerRequestFilter {
    private final JwtService jwtService;
    private final UserDetailsService userDetailsService;

    @Override
    protected void doFilterInternal(
            @NonNull HttpServletRequest request,
            @NonNull HttpServletResponse response,
            @NonNull FilterChain filterChain
    ) throws ServletException, IOException {
        if (request.getServletPath().contains("/api/v1/auth")) {
            filterChain.doFilter(request, response);
            return;
        }
        log.info("Authentication Filter execution started");
        try {
            final String authHeader = request.getHeader("Authorization");
            if (authHeader == null || !authHeader.startsWith("Bearer")) {
                log.info("Filter execution stopped as auth header is invalid/empty");
                sendForbiddenResponse(response, "Auth header cannot be empty");
                return;
            }
            final String token = authHeader.substring(7);
            log.info("Token: {}", token);
            if(jwtService.isBlacklisted(token)){
                log.info("Token has been revoked!");
                sendForbiddenResponse(response, "Your token has been revoked. Please contact support.");
                return;
            }
            final String userEmail = jwtService.extractUsername(token);
            //final List<String> roles = jwtService.extractRoles(token);
//            List<SimpleGrantedAuthority> authorities = roles.stream().map(role-> "ROLE_"+role)
//                    .map(SimpleGrantedAuthority::new)
//                    .toList();
            if (userEmail != null && SecurityContextHolder.getContext().getAuthentication() == null) {
                UserDetails userDetails = this.userDetailsService.loadUserByUsername(userEmail);

                log.info("User fetched from Database: {}", userDetails);
                if (jwtService.isTokenValid(token, userDetails)) {
                    log.info("Token validated successfully");
                    UsernamePasswordAuthenticationToken authToken = new UsernamePasswordAuthenticationToken(
                            userDetails,
                            null,
                            userDetails.getAuthorities().stream().map(role -> "ROLE_" + role)
                                    .map(SimpleGrantedAuthority::new)
                                    .toList());

                    authToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
                    SecurityContextHolder.getContext().setAuthentication(authToken);
                    log.info("SecurityContextHolder updated with authenticated status");
                }
            }
        } catch (Exception e) {
            log.info(e.getMessage());
        }
        log.info("Authentication Filter process completed");
        filterChain.doFilter(request, response);
    }
    private void sendForbiddenResponse(HttpServletResponse response, String message) throws IOException {
        response.setStatus(HttpServletResponse.SC_FORBIDDEN);
        response.setContentType("application/json");
        response.setCharacterEncoding("UTF-8");
        response.getWriter().write("{\"error\": \"" + message + "\"}");
    }
}
