using System.Text.Json.Serialization;
using System.Text.Json;
using TuningStore.Data;
using TuningStore.Repositories;
using TuningStore.Services;
using TuningStore.Middleware;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Authorization;
using TuningStore.Authorization.Requirements;
using TuningStore.Authorization.Policies;
using System.Text;
using Scalar.AspNetCore;
using Microsoft.OpenApi.Models;
var builder = WebApplication.CreateBuilder(args);


builder.Services.AddControllers().AddJsonOptions(options =>
{
    options.JsonSerializerOptions.Converters.Add(new JsonStringEnumConverter());
    options.JsonSerializerOptions.PropertyNamingPolicy = JsonNamingPolicy.CamelCase;
    options.JsonSerializerOptions.ReferenceHandler = ReferenceHandler.IgnoreCycles;

});

builder.Services.AddCors(options =>
{
    options.AddPolicy("AllowReactApp", policy =>
        policy.WithOrigins("http://localhost:5173")
              .AllowAnyHeader()
              .AllowAnyMethod()
              .AllowCredentials());
});
builder.Services.AddDbContext<AppDbContext>(options => options.UseSqlServer(builder.Configuration.GetConnectionString("DefaultConnection")));

builder.Services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
    .AddJwtBearer(options =>
    {
        options.Events = new JwtBearerEvents
        {
            OnMessageReceived = context =>
            {
                var authHeader = context.Request.Headers["Authorization"].FirstOrDefault();
                if (authHeader != null && authHeader.StartsWith("Bearer "))
                {
                    context.Token = authHeader.Substring("Bearer ".Length).Trim();
                }

                return Task.CompletedTask;
            }
        };

        options.TokenValidationParameters = new TokenValidationParameters
        {
            ValidateIssuer = true,
            ValidateAudience = true,
            ValidateLifetime = true,
            ValidateIssuerSigningKey = true,
            ValidIssuer = builder.Configuration["Jwt:Issuer"],
            ValidAudience = builder.Configuration["Jwt:Audience"],
            IssuerSigningKey = new SymmetricSecurityKey(
                Encoding.UTF8.GetBytes(builder.Configuration["Jwt:SecretKey"]!)),
            ClockSkew = TimeSpan.Zero,
            RequireExpirationTime = true,
            RequireSignedTokens = true,
            LifetimeValidator = (notBefore, expires, token, validationParameters) =>
            {
                var now = DateTime.UtcNow;
                return notBefore <= now && expires > now;
            }
        };

        options.RequireHttpsMetadata = !builder.Environment.IsDevelopment();
        options.SaveToken = false;
    });

builder.Services.AddAuthorization(options =>
{
    options.AddPolicy(AuthorizationPolicies.AdminOnly, policy =>
        policy.RequireRole("Admin"));

    options.AddPolicy(AuthorizationPolicies.ResourceOwner, policy =>
        policy.Requirements.Add(new ResourceOwnerRequirement()));

    options.AddPolicy(AuthorizationPolicies.UserOrAdmin, policy =>
        policy.RequireRole("User", "Admin"));
});
builder.Services.AddScoped<IAuthorizationHandler, ResourceOwnerHandler>();
builder.Services.AddScoped<IRefreshTokenRepository, RefreshTokenRepository>();
builder.Services.AddHttpContextAccessor();
builder.Services.AddScoped<IUserRepository, UserRepository>();
builder.Services.AddScoped<IUserService, UserService>();
builder.Services.AddScoped<IBrandRepository, BrandRepository>();
builder.Services.AddScoped<IBrandService, BrandService>();
builder.Services.AddScoped<IModelRepository, ModelRepository>();
builder.Services.AddScoped<IModelService, ModelService>();
builder.Services.AddScoped<IJwtService, JwtService>();
builder.Services.AddScoped<ISpecificationRepository, SpecificationRepository>();
builder.Services.AddScoped<ISpecificationService, SpecificationService>();
builder.Services.AddScoped<IPartRepository, PartRepository>();
builder.Services.AddScoped<IPartService, PartService>();
builder.Services.AddScoped<IFaqRepository, FaqRepository>();
builder.Services.AddScoped<IFaqService, FaqService>();
builder.Services.AddOpenApi(options =>
{
    options.AddDocumentTransformer((document, context, cancellationToken) =>
    {
        document.Info = new()
        {
            Title = "TuningStore API",
            Version = "v1",
            Description = "API for car tuning parts management system"
        };

        document.Components ??= new();
        document.Components.SecuritySchemes = new Dictionary<string, OpenApiSecurityScheme>
        {
            ["Bearer"] = new()
            {
                Type = SecuritySchemeType.Http,
                Scheme = "bearer",
                BearerFormat = "JWT"
            }
        };

        document.SecurityRequirements = new List<OpenApiSecurityRequirement>
        {
            new()
            {
                [new OpenApiSecurityScheme
                {
                    Reference = new OpenApiReference
                    {
                        Type = ReferenceType.SecurityScheme,
                        Id = "Bearer"
                    }
                }] = Array.Empty<string>()
            }
        };

        return Task.CompletedTask;
    });
});

var app = builder.Build();

app.MapOpenApi();
app.MapScalarApiReference(options =>
{
    options
        .WithTitle("TuningStore API")
        .WithTheme(ScalarTheme.Purple)
        .WithDefaultHttpClient(ScalarTarget.CSharp, ScalarClient.HttpClient);
});

app.UseHttpsRedirection();
app.UseCors("AllowReactApp");
app.UseMiddleware<ErrorHandlingMiddleware>();
app.UseAuthentication();
app.UseAuthorization();
app.MapControllers();

app.Run();
