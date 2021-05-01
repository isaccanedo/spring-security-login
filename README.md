## Spring Security Form Login

# 1. Introdução
Este artigo se concentrará em Login com Spring Security. Vamos construir sobre o exemplo anterior simples do Spring MVC, já que essa é uma parte necessária da configuração do aplicativo da web junto com o mecanismo de login.

# 2. As dependências do Maven
Ao trabalhar com Spring Boot, o spring-boot-starter-security starter incluirá automaticamente todas as dependências, como spring-security-core, spring-security-web e spring-security-config, entre outras:

```
<dependency>
    <groupId>org.springframework.boot</groupId>
    <artifactId>spring-boot-starter-security</artifactId>
    <version>2.3.3.RELEASE</version>
</dependency>
```

Caso não usemos Spring Boot, consulte o artigo Spring Security com Maven, que descreve como adicionar todas as dependências necessárias. Tanto o spring-security-web padrão quanto o spring-security-config serão necessários.

# 3. Configuração do Spring Security Java
Vamos começar criando uma classe de configuração Spring Security que estende WebSecurityConfigurerAdapter.

Ao adicionar @EnableWebSecurity, obtemos suporte de integração Spring Security e MVC:

```
@Configuration
@EnableWebSecurity
public class SecSecurityConfig extends WebSecurityConfigurerAdapter {

    @Override
    protected void configure(final AuthenticationManagerBuilder auth) throws Exception {
        // authentication manager (see below)
    }

    @Override
    protected void configure(final HttpSecurity http) throws Exception {
        // http builder configurations for authorize requests and form login (see below)
    }
}
```

Neste exemplo, usamos a autenticação na memória e definimos 3 usuários.

Em seguida, examinamos os elementos que usamos para criar a configuração de login do formulário.

Vamos construir nosso gerenciador de autenticação primeiro.

### 3.1. Gerenciador de autenticação
O provedor de autenticação é apoiado por uma implementação simples na memória - especificamente **InMemoryUserDetailsManager**. Isso é útil para prototipagem rápida quando um mecanismo de persistência completo ainda não é necessário:

```
protected void configure(final AuthenticationManagerBuilder auth) throws Exception {
    auth.inMemoryAuthentication()
        .withUser("user1").password(passwordEncoder().encode("user1Pass")).roles("USER")
        .and()
        .withUser("user2").password(passwordEncoder().encode("user2Pass")).roles("USER")
        .and()
        .withUser("admin").password(passwordEncoder().encode("adminPass")).roles("ADMIN");
}
```

Aqui, configuramos três usuários com nome de usuário, senha e função codificados.

A partir do Spring 5, também precisamos definir um codificador de senha. Em nosso exemplo, usamos o **BCryptPasswordEncoder**:

```
@Bean 
public PasswordEncoder passwordEncoder() { 
    return new BCryptPasswordEncoder(); 
}
```

A seguir, vamos configurar o HttpSecurity.

### 3.2. Configuração para autorizar solicitações
Começamos fazendo as configurações necessárias para Autorizar Solicitações.

Aqui, estamos permitindo acesso anônimo em /login para que os usuários possam se autenticar. Restringindo /admin para funções de ADMIN e protegendo todo o resto:

```
@Override
protected void configure(final HttpSecurity http) throws Exception {
    http
      .csrf().disable()
      .authorizeRequests()
      .antMatchers("/admin/**").hasRole("ADMIN")
      .antMatchers("/anonymous*").anonymous()
      .antMatchers("/login*").permitAll()
      .anyRequest().authenticated()
      .and()
      // ...
}
```

Observe que a ordem dos elementos antMatchers () é significativa - as regras mais específicas precisam vir primeiro, seguidas pelas mais gerais.

### 3.3. Configuração para login de formulário
A seguir, estendemos a configuração acima para login e logout do formulário:

```
@Override
protected void configure(final HttpSecurity http) throws Exception {
    http
      // ...
      .and()
      .formLogin()
      .loginPage("/login.html")
      .loginProcessingUrl("/perform_login")
      .defaultSuccessUrl("/homepage.html", true)
      .failureUrl("/login.html?error=true")
      .failureHandler(authenticationFailureHandler())
      .and()
      .logout()
      .logoutUrl("/perform_logout")
      .deleteCookies("JSESSIONID")
      .logoutSuccessHandler(logoutSuccessHandler());
}
```

- loginPage() - a página de login personalizada;
- loginProcessingUrl() - a URL para a qual enviar o nome de usuário e a senha;
- defaultSuccessUrl() - a página inicial após um login bem-sucedido;
- failureUrl() - a página de destino após um login malsucedido;
- logoutUrl() - o logout personalizado.

4. Adicione Spring Security ao aplicativo da Web
Para usar a configuração Spring Security definida acima, precisamos anexá-la ao aplicativo da web.

Usaremos o WebApplicationInitializer, portanto, não precisamos fornecer nenhum web.xml:

```
public class AppInitializer implements WebApplicationInitializer {

    @Override
    public void onStartup(ServletContext sc) {

        AnnotationConfigWebApplicationContext root = new AnnotationConfigWebApplicationContext();
        root.register(SecSecurityConfig.class);

        sc.addListener(new ContextLoaderListener(root));

        sc.addFilter("securityFilter", new DelegatingFilterProxy("springSecurityFilterChain"))
          .addMappingForUrlPatterns(null, false, "/*");
    }
}
```

Observe que este inicializador não é necessário se estivermos usando um aplicativo Spring Boot. Dê uma olhada em nosso artigo sobre configuração automática de segurança do Spring Boot para obter mais detalhes sobre como a configuração de segurança é carregada no Spring Boot.

# 5. A configuração XML do Spring Security
Vamos também dar uma olhada na configuração XML correspondente.

O projeto geral está usando a configuração Java, portanto, precisamos importar o arquivo de configuração XML por meio de uma classe **@Configuration** Java:

```
@Configuration
@ImportResource({ "classpath:webSecurityConfig.xml" })
public class SecSecurityConfig {
   public SecSecurityConfig() {
      super();
   }
}
```

E a configuração XML do Spring Security - webSecurityConfig.xml:

```
<http use-expressions="true">
    <intercept-url pattern="/login*" access="isAnonymous()" />
    <intercept-url pattern="/**" access="isAuthenticated()"/>

    <form-login login-page='/login.html' 
      default-target-url="/homepage.html" 
      authentication-failure-url="/login.html?error=true" />
    <logout logout-success-url="/login.html" />
</http>

<authentication-manager>
    <authentication-provider>
        <user-service>
            <user name="user1" password="user1Pass" authorities="ROLE_USER" />
        </user-service>
        <password-encoder ref="encoder" />
    </authentication-provider>
</authentication-manager>

<beans:bean id="encoder" 
  class="org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder">
</beans:bean>
```

# 6. O web.xml
Antes da introdução do Spring 4, costumávamos definir a configuração do Spring Security no web.xml - apenas um filtro adicional adicionado ao Spring MVC web.xml padrão:

```
<display-name>Spring Secured Application</display-name>

<!-- Spring MVC -->
<!-- ... -->

<!-- Spring Security -->
<filter>
    <filter-name>springSecurityFilterChain</filter-name>
    <filter-class>org.springframework.web.filter.DelegatingFilterProxy</filter-class>
</filter>
<filter-mapping>
    <filter-name>springSecurityFilterChain</filter-name>
    <url-pattern>/*</url-pattern>
</filter-mapping>
```

O filtro - **DelegatingFilterProxy** - simplesmente delega para um bean gerenciado pelo Spring - o FilterChainProxy - que por si só pode se beneficiar do gerenciamento do ciclo de vida do Spring bean completo e tal.

# 7. O formulário de login
A página do formulário de login será registrada com Spring MVC usando o mecanismo direto para mapear nomes de visualizações para URLs sem a necessidade de um controlador explícito entre:

```
registry.addViewController("/login.html");
```

o dele, é claro, corresponde ao login.jsp:

```
<html>
<head></head>
<body>
   <h1>Login</h1>
   <form name='f' action="login" method='POST'>
      <table>
         <tr>
            <td>User:</td>
            <td><input type='text' name='username' value=''></td>
         </tr>
         <tr>
            <td>Password:</td>
            <td><input type='password' name='password' /></td>
         </tr>
         <tr>
            <td><input name="submit" type="submit" value="submit" /></td>
         </tr>
      </table>
  </form>
</body>
</html>
```

O formulário de login do Spring tem os seguintes artefatos relevantes:

- login - a URL onde o formulário é POSTADO para acionar o processo de autenticação;
- nome de usuário - o nome de usuário;
- senha - a senha.

# 8. Configuração adicional do Spring Login
Discutimos brevemente algumas configurações do mecanismo de login quando apresentamos a configuração Spring Security acima - vamos entrar em alguns detalhes agora.

Um motivo para substituir a maioria dos padrões no Spring Security é ocultar o fato de que o aplicativo é protegido com Spring Security e minimizar as informações que um invasor potencial conhece sobre o aplicativo.

Totalmente configurado, o elemento de login tem a seguinte aparência:

```
@Override
protected void configure(HttpSecurity http) throws Exception {
    http.formLogin()
      .loginPage("/login.html")
      .loginProcessingUrl("/perform_login")
      .defaultSuccessUrl("/homepage.html",true)
      .failureUrl("/login.html?error=true")
}
```

Ou a configuração XML correspondente:

```
<form-login 
  login-page='/login.html' 
  login-processing-url="/perform_login" 
  default-target-url="/homepage.html"
  authentication-failure-url="/login.html?error=true" 
  always-use-default-target="true"/>
```

### 8.1. A página de login
A seguir, vamos ver como podemos configurar uma página de login personalizada usando o 
método loginPage():

```
http.formLogin()
  .loginPage("/login.html")
```

Ou, via configuração XML:

```
login-page='/login.html'
```

Se não especificarmos isso, Spring Security irá gerar um formulário de login muito básico na URL / login.

### 8.2. O URL POST para login
A URL padrão onde o Login do Spring irá POSTAR para acionar o processo de autenticação é /login, que costumava ser /j_spring_security_check antes do Spring Security 4.

Podemos usar o método loginProcessingUrl para substituir este URL:

```
http.formLogin()
  .loginProcessingUrl("/perform_login")
```

Ou, via configuração XML:

```
login-processing-url="/perform_login"
```

Um bom motivo para substituir essa URL padrão é ocultar o fato de que o aplicativo está realmente protegido com Spring Security - essas informações não devem estar disponíveis externamente.

### 8.3. A página de destino do sucesso
Após um processo de login bem-sucedido, o usuário é redirecionado para uma página - que por padrão é a raiz do aplicativo da web.

Podemos substituir isso por meio do método defaultSuccessUrl():

```
http.formLogin()
  .defaultSuccessUrl("/homepage.html")
```

Ou com configuração XML:

```
default-target-url="/homepage.html"
```

No caso de always-use-default-target ser definido como true, o usuário é sempre redirecionado para esta página. Se esse atributo for definido como falso, o usuário será redirecionado para a página anterior que desejava visitar antes de ser solicitado a autenticar.

### 8.4. A página de destino em caso de falha
Da mesma forma que a página de login, a página de falha de login é gerada automaticamente pelo Spring Security em / login? Erro por padrão.

Para substituir isso, podemos usar o método failureUrl():

```
http.formLogin()
  .failureUrl("/login.html?error=true")
```

Ou com XML:

```
authentication-failure-url="/login.html?error=true"
```

# 9. Conclusão
Neste exemplo de login do Spring, configuramos um processo de autenticação simples - discutimos o formulário de login do Spring Security, a configuração de segurança e algumas das personalizações mais avançadas disponíveis.

Quando o projeto é executado localmente, o HTML de amostra pode ser acessado em:

```
http://localhost:8080/spring-security-mvc-login/login.html
```