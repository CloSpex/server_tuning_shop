
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
using TuningStore.DTOs;
using TuningStore.Models;
using System.Text;
using Scalar.AspNetCore;
using Microsoft.OpenApi.Models;
using Microsoft.OpenApi.Any;
var builder = WebApplication.CreateBuilder(args);


builder.Services.AddControllers().AddJsonOptions(options =>
{
    options.JsonSerializerOptions.Converters.Add(new JsonStringEnumConverter());
    options.JsonSerializerOptions.PropertyNamingPolicy = JsonNamingPolicy.CamelCase;
    options.JsonSerializerOptions.ReferenceHandler = ReferenceHandler.IgnoreCycles;

});

builder.Services.AddCors(options =>
{
    var allowedOrigins = builder.Configuration["AllowedOrigins"]?.Split(";")
                        ?? new[] { "http://localhost:5173" };
    foreach (var item in allowedOrigins)
    {
        Console.WriteLine(item);
    }
    var originsList = allowedOrigins
     .SelectMany(origin =>
     {
         var trimmed = origin.Trim();
         if (string.IsNullOrWhiteSpace(trimmed)) return Enumerable.Empty<string>();

         return new[]
         {
            trimmed,
            trimmed.StartsWith("http://") ? trimmed.Replace("http://", "https://") :
            trimmed.StartsWith("https://") ? trimmed.Replace("https://", "http://") :
            null
         }.Where(x => x != null)!;
     })
     .Distinct()
     .ToArray();

    options.AddPolicy("AllowReactApp", policy =>
        policy.WithOrigins(originsList)
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

builder.Services.AddScoped<IPartCategoryRepository, PartCategoryRepository>();
builder.Services.AddScoped<IPartCategoryService, PartCategoryService>();

builder.Services.AddScoped(typeof(ICarEnumRepository<>), typeof(CarEnumRepository<>));
builder.Services.AddScoped<ICarEnumService<EngineType, EngineTypeDto, CreateEngineTypeDto, UpdateEngineTypeDto>>(sp =>
    new CarEnumService<EngineType, EngineTypeDto, CreateEngineTypeDto, UpdateEngineTypeDto>(
        sp.GetRequiredService<ICarEnumRepository<EngineType>>(),
        e => new EngineTypeDto { Id = e.Id, Name = e.Name },
        (e, dto) => { e.Name = dto.Name; },
        (e, dto) => { if (!string.IsNullOrWhiteSpace(dto.Name)) e.Name = dto.Name; }
    ));

builder.Services.AddScoped<ICarEnumService<BodyType, BodyTypeDto, CreateBodyTypeDto, UpdateBodyTypeDto>>(sp =>
    new CarEnumService<BodyType, BodyTypeDto, CreateBodyTypeDto, UpdateBodyTypeDto>(
        sp.GetRequiredService<ICarEnumRepository<BodyType>>(),
        e => new BodyTypeDto { Id = e.Id, Name = e.Name },
        (e, dto) => { e.Name = dto.Name; },
        (e, dto) => { if (!string.IsNullOrWhiteSpace(dto.Name)) e.Name = dto.Name; }
    ));

builder.Services.AddScoped<ICarEnumService<TransmissionType, TransmissionTypeDto, CreateTransmissionTypeDto, UpdateTransmissionTypeDto>>(sp =>
    new CarEnumService<TransmissionType, TransmissionTypeDto, CreateTransmissionTypeDto, UpdateTransmissionTypeDto>(
        sp.GetRequiredService<ICarEnumRepository<TransmissionType>>(),
        e => new TransmissionTypeDto { Id = e.Id, Name = e.Name },
        (e, dto) => { e.Name = dto.Name; },
        (e, dto) => { if (!string.IsNullOrWhiteSpace(dto.Name)) e.Name = dto.Name; }
    ));



builder.Services.AddScoped<IPartService, PartService>();
builder.Services.AddScoped<IFaqRepository, FaqRepository>();
builder.Services.AddScoped<IFaqService, FaqService>();
builder.Services.AddScoped<IOrderRepository, OrderRepository>();
builder.Services.AddScoped<IOrderService, OrderService>();
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
if (app.Environment.IsDevelopment())
{
    app.MapScalarApiReference(options =>
    {
        options
            .WithTitle("TuningStore API")
            .WithTheme(ScalarTheme.Purple)
            .WithDefaultHttpClient(ScalarTarget.CSharp, ScalarClient.HttpClient);
    });
}
/*
builder.Services.AddOpenApi(options =>
{
    options.AddSchemaTransformer((schema, context, cancellationToken) =>
 {
     schema.Example = context.JsonTypeInfo.Type.Name switch
     {
         nameof(CreateBrandDto) => new OpenApiObject { ["name"] = new OpenApiString("BMW"), ["description"] = new OpenApiString("German luxury vehicles") },
         nameof(UpdateBrandDto) => new OpenApiObject { ["name"] = new OpenApiString("Audi"), ["description"] = new OpenApiString("Premium German cars") },
         nameof(BrandDto) => new OpenApiObject { ["id"] = new OpenApiInteger(1), ["name"] = new OpenApiString("BMW"), ["description"] = new OpenApiString("German luxury vehicles"), ["createdBy"] = new OpenApiInteger(1), ["updatedBy"] = new OpenApiInteger(1), ["createdAt"] = new OpenApiString("2024-01-15T10:30:00Z"), ["updatedAt"] = new OpenApiString("2024-01-15T10:30:00Z") },

         nameof(CreateModelDto) => new OpenApiObject { ["name"] = new OpenApiString("M3"), ["brandId"] = new OpenApiInteger(1) },
         nameof(UpdateModelDto) => new OpenApiObject { ["name"] = new OpenApiString("M5"), ["brandId"] = new OpenApiInteger(1) },
         nameof(ModelDto) => new OpenApiObject { ["id"] = new OpenApiInteger(1), ["name"] = new OpenApiString("M3"), ["brandId"] = new OpenApiInteger(1), ["createdBy"] = new OpenApiInteger(1), ["updatedBy"] = new OpenApiInteger(1), ["createdAt"] = new OpenApiString("2024-01-15T10:30:00Z"), ["updatedAt"] = new OpenApiString("2024-01-15T10:30:00Z") },

         nameof(CreateSpecificationDto) => new OpenApiObject { ["modelId"] = new OpenApiInteger(1), ["engineTypeId"] = new OpenApiInteger(1), ["transmissionTypeId"] = new OpenApiInteger(2), ["bodyTypeId"] = new OpenApiInteger(3), ["volumeLitres"] = new OpenApiDouble(3.0), ["powerKilowatts"] = new OpenApiDouble(317), ["yearStart"] = new OpenApiInteger(2020), ["yearEnd"] = new OpenApiInteger(2024) },
         nameof(UpdateSpecificationDto) => new OpenApiObject { ["modelId"] = new OpenApiInteger(1), ["engineTypeId"] = new OpenApiInteger(2), ["transmissionTypeId"] = new OpenApiInteger(1), ["bodyTypeId"] = new OpenApiInteger(3), ["volumeLitres"] = new OpenApiDouble(4.4), ["powerKilowatts"] = new OpenApiDouble(460), ["yearStart"] = new OpenApiInteger(2021), ["yearEnd"] = new OpenApiInteger(2024) },
         nameof(SpecificationDto) => new OpenApiObject { ["id"] = new OpenApiInteger(1), ["modelId"] = new OpenApiInteger(1), ["engineTypeId"] = new OpenApiInteger(1), ["transmissionTypeId"] = new OpenApiInteger(2), ["bodyTypeId"] = new OpenApiInteger(3), ["volumeLitres"] = new OpenApiDouble(3.0), ["powerKilowatts"] = new OpenApiDouble(317), ["yearStart"] = new OpenApiInteger(2020), ["yearEnd"] = new OpenApiInteger(2024), ["createdBy"] = new OpenApiInteger(1), ["createdAt"] = new OpenApiString("2024-01-15T10:30:00Z"), ["updatedAt"] = new OpenApiString("2024-01-15T10:30:00Z") },

         nameof(CreateEngineTypeDto) => new OpenApiObject { ["name"] = new OpenApiString("Inline-6") },
         nameof(UpdateEngineTypeDto) => new OpenApiObject { ["name"] = new OpenApiString("V8") },
         nameof(EngineTypeDto) => new OpenApiObject { ["id"] = new OpenApiInteger(1), ["name"] = new OpenApiString("Inline-6") },
         nameof(CreateTransmissionTypeDto) => new OpenApiObject { ["name"] = new OpenApiString("Manual") },
         nameof(UpdateTransmissionTypeDto) => new OpenApiObject { ["name"] = new OpenApiString("Automatic") },
         nameof(TransmissionTypeDto) => new OpenApiObject { ["id"] = new OpenApiInteger(1), ["name"] = new OpenApiString("Manual") },
         nameof(CreateBodyTypeDto) => new OpenApiObject { ["name"] = new OpenApiString("Sedan") },
         nameof(UpdateBodyTypeDto) => new OpenApiObject { ["name"] = new OpenApiString("Coupe") },
         nameof(BodyTypeDto) => new OpenApiObject { ["id"] = new OpenApiInteger(1), ["name"] = new OpenApiString("Sedan") },

         nameof(CreatePartCategoryDto) => new OpenApiObject { ["name"] = new OpenApiString("Exhaust Systems"), ["isExterior"] = new OpenApiBoolean(false) },
         nameof(UpdatePartCategoryDto) => new OpenApiObject { ["name"] = new OpenApiString("Body Kits"), ["isExterior"] = new OpenApiBoolean(true) },
         nameof(PartCategoryDto) => new OpenApiObject { ["id"] = new OpenApiInteger(1), ["name"] = new OpenApiString("Exhaust Systems"), ["isExterior"] = new OpenApiBoolean(false) },

         nameof(CreatePartDto) => new OpenApiObject { ["name"] = new OpenApiString("M Performance Exhaust"), ["price"] = new OpenApiDouble(2499.99), ["quantity"] = new OpenApiInteger(5), ["partCategoryId"] = new OpenApiInteger(1), ["color"] = new OpenApiString("#1a1a1a"), ["imagePath"] = new OpenApiString("images/exhaust.jpg"), ["carSpecificationId"] = new OpenApiInteger(1) },
         nameof(UpdatePartDto) => new OpenApiObject { ["name"] = new OpenApiString("Akrapovic Exhaust"), ["price"] = new OpenApiDouble(3999.99), ["quantity"] = new OpenApiInteger(3), ["partCategoryId"] = new OpenApiInteger(1), ["color"] = new OpenApiString("#2a2a2a"), ["imagePath"] = new OpenApiString("images/akrapovic.jpg"), ["carSpecificationId"] = new OpenApiInteger(1) },
         nameof(PartDto) => new OpenApiObject { ["id"] = new OpenApiInteger(1), ["name"] = new OpenApiString("M Performance Exhaust"), ["price"] = new OpenApiDouble(2499.99), ["color"] = new OpenApiString("#1a1a1a"), ["quantity"] = new OpenApiInteger(5), ["imagePath"] = new OpenApiString("images/exhaust.jpg"), ["carSpecificationId"] = new OpenApiInteger(1), ["partCategoryId"] = new OpenApiInteger(1), ["createdBy"] = new OpenApiInteger(1), ["createdAt"] = new OpenApiString("2024-01-15T10:30:00Z"), ["updatedAt"] = new OpenApiString("2024-01-15T10:30:00Z") },

         nameof(CreateFAQDto) => new OpenApiObject { ["question"] = new OpenApiString("Do you ship internationally?"), ["answer"] = new OpenApiString("Yes, we ship to most countries worldwide. Shipping costs vary by destination.") },
         nameof(UpdateFAQDto) => new OpenApiObject { ["question"] = new OpenApiString("What payment methods do you accept?"), ["answer"] = new OpenApiString("We accept all major credit cards, PayPal, and bank transfers.") },
         nameof(FAQDto) => new OpenApiObject { ["id"] = new OpenApiInteger(1), ["question"] = new OpenApiString("Do you ship internationally?"), ["answer"] = new OpenApiString("Yes, we ship to most countries worldwide."), ["createdBy"] = new OpenApiInteger(1), ["createdAt"] = new OpenApiString("2024-01-15T10:30:00Z"), ["updatedAt"] = new OpenApiString("2024-01-15T10:30:00Z") },

         nameof(CreateOrderItemDto) => new OpenApiObject { ["partId"] = new OpenApiInteger(1), ["quantity"] = new OpenApiInteger(2) },
         nameof(CreateOrderDto) => new OpenApiObject { ["items"] = new OpenApiArray { new OpenApiObject { ["partId"] = new OpenApiInteger(1), ["quantity"] = new OpenApiInteger(2) }, new OpenApiObject { ["partId"] = new OpenApiInteger(3), ["quantity"] = new OpenApiInteger(1) } } },
         nameof(UpdateOrderDto) => new OpenApiObject { ["status"] = new OpenApiString("Shipped") },
         nameof(OrderItemDto) => new OpenApiObject { ["partId"] = new OpenApiInteger(1), ["partName"] = new OpenApiString("M Performance Exhaust"), ["quantity"] = new OpenApiInteger(2), ["unitPrice"] = new OpenApiDouble(2499.99) },
         nameof(OrderDto) => new OpenApiObject { ["id"] = new OpenApiInteger(1), ["orderDate"] = new OpenApiString("2024-01-15T10:30:00Z"), ["status"] = new OpenApiString("Pending"), ["totalPrice"] = new OpenApiDouble(4999.98), ["items"] = new OpenApiArray { new OpenApiObject { ["partId"] = new OpenApiInteger(1), ["partName"] = new OpenApiString("M Performance Exhaust"), ["quantity"] = new OpenApiInteger(2), ["unitPrice"] = new OpenApiDouble(2499.99) } }, ["createdBy"] = new OpenApiInteger(1), ["createdAt"] = new OpenApiString("2024-01-15T10:30:00Z"), ["updatedAt"] = new OpenApiString("2024-01-15T10:30:00Z") },

         nameof(CreateUserDto) => new OpenApiObject { ["username"] = new OpenApiString("johndoe"), ["email"] = new OpenApiString("john@example.com"), ["password"] = new OpenApiString("SecurePass123") },
         nameof(UpdateUserDto) => new OpenApiObject { ["username"] = new OpenApiString("johndoe2"), ["email"] = new OpenApiString("john.doe@example.com"), ["password"] = new OpenApiString("NewPass456") },
         nameof(UpdateRoleDto) => new OpenApiObject { ["role"] = new OpenApiString("Admin") },
         nameof(UserDto) => new OpenApiObject { ["id"] = new OpenApiInteger(1), ["username"] = new OpenApiString("johndoe"), ["email"] = new OpenApiString("john@example.com"), ["role"] = new OpenApiString("User"), ["createdBy"] = new OpenApiInteger(1), ["createdAt"] = new OpenApiString("2024-01-15T10:30:00Z"), ["updatedAt"] = new OpenApiString("2024-01-15T10:30:00Z") },
         nameof(LoginDto) => new OpenApiObject { ["username"] = new OpenApiString("johndoe"), ["password"] = new OpenApiString("SecurePass123") },
         nameof(LoginResponseDto) => new OpenApiObject { ["accessToken"] = new OpenApiString("eyJhbGc..."), ["refreshToken"] = new OpenApiString("dGVzdC..."), ["expiresAt"] = new OpenApiString("2024-01-15T11:30:00Z"), ["user"] = new OpenApiObject { ["id"] = new OpenApiInteger(1), ["username"] = new OpenApiString("johndoe"), ["email"] = new OpenApiString("john@example.com"), ["role"] = new OpenApiString("User") } },
         nameof(RefreshTokenDto) => new OpenApiObject { ["accessToken"] = new OpenApiString("eyJhbGc..."), ["refreshToken"] = new OpenApiString("dGVzdC...") },
         nameof(TokenResponseDto) => new OpenApiObject { ["accessToken"] = new OpenApiString("eyJhbGc..."), ["refreshToken"] = new OpenApiString("dGVzdC..."), ["expiresAt"] = new OpenApiString("2024-01-15T11:30:00Z") },

         _ => null
     };
     return Task.CompletedTask;
 });
    options.AddDocumentTransformer(async (document, context, cancellationToken) =>
    {
        document.Info ??= new OpenApiInfo
        {
            Title = "TuningStore API",
            Version = "v1",
            Description = "API for car tuning parts management system"
        };

        document.Components ??= new OpenApiComponents();
        document.Components.SecuritySchemes ??= new Dictionary<string, OpenApiSecurityScheme>();
        document.Components.SecuritySchemes["Bearer"] = new OpenApiSecurityScheme
        {
            Type = SecuritySchemeType.Http,
            Scheme = "bearer",
            BearerFormat = "JWT"
        };

        document.SecurityRequirements ??= new List<OpenApiSecurityRequirement>();
        document.SecurityRequirements.Add(new OpenApiSecurityRequirement
        {
            [new OpenApiSecurityScheme
            {
                Reference = new OpenApiReference
                {
                    Type = ReferenceType.SecurityScheme,
                    Id = "Bearer"
                }
            }] = Array.Empty<string>()
        });

        await Task.CompletedTask;
    });
    options.AddOperationTransformer((operation, context, cancellationToken) =>
{
    foreach (var response in operation.Responses)
    {
        if (response.Value.Content != null)
        {
            foreach (var content in response.Value.Content)
            {
                var schemaRef = content.Value.Schema?.Reference?.Id;

                if (schemaRef == nameof(BrandDto))
                    content.Value.Example = new OpenApiObject { ["id"] = new OpenApiInteger(1), ["name"] = new OpenApiString("BMW"), ["description"] = new OpenApiString("German luxury vehicles"), ["createdBy"] = new OpenApiInteger(1), ["updatedBy"] = new OpenApiInteger(1), ["createdAt"] = new OpenApiString("2024-01-15T10:30:00Z"), ["updatedAt"] = new OpenApiString("2024-01-15T10:30:00Z") };
                else if (schemaRef == nameof(ModelDto))
                    content.Value.Example = new OpenApiObject { ["id"] = new OpenApiInteger(1), ["name"] = new OpenApiString("M3"), ["brandId"] = new OpenApiInteger(1), ["createdBy"] = new OpenApiInteger(1), ["updatedBy"] = new OpenApiInteger(1), ["createdAt"] = new OpenApiString("2024-01-15T10:30:00Z"), ["updatedAt"] = new OpenApiString("2024-01-15T10:30:00Z") };
                else if (schemaRef == nameof(SpecificationDto))
                    content.Value.Example = new OpenApiObject { ["id"] = new OpenApiInteger(1), ["modelId"] = new OpenApiInteger(1), ["engineTypeId"] = new OpenApiInteger(1), ["transmissionTypeId"] = new OpenApiInteger(2), ["bodyTypeId"] = new OpenApiInteger(3), ["volumeLitres"] = new OpenApiDouble(3.0), ["powerKilowatts"] = new OpenApiDouble(317), ["yearStart"] = new OpenApiInteger(2020), ["yearEnd"] = new OpenApiInteger(2024), ["createdBy"] = new OpenApiInteger(1), ["createdAt"] = new OpenApiString("2024-01-15T10:30:00Z"), ["updatedAt"] = new OpenApiString("2024-01-15T10:30:00Z") };
                else if (schemaRef == nameof(EngineTypeDto))
                    content.Value.Example = new OpenApiObject { ["id"] = new OpenApiInteger(1), ["name"] = new OpenApiString("Inline-6") };
                else if (schemaRef == nameof(TransmissionTypeDto))
                    content.Value.Example = new OpenApiObject { ["id"] = new OpenApiInteger(1), ["name"] = new OpenApiString("Manual") };
                else if (schemaRef == nameof(BodyTypeDto))
                    content.Value.Example = new OpenApiObject { ["id"] = new OpenApiInteger(1), ["name"] = new OpenApiString("Sedan") };
                else if (schemaRef == nameof(PartCategoryDto))
                    content.Value.Example = new OpenApiObject { ["id"] = new OpenApiInteger(1), ["name"] = new OpenApiString("Exhaust Systems"), ["isExterior"] = new OpenApiBoolean(false) };
                else if (schemaRef == nameof(PartDto))
                    content.Value.Example = new OpenApiObject { ["id"] = new OpenApiInteger(1), ["name"] = new OpenApiString("M Performance Exhaust"), ["price"] = new OpenApiDouble(2499.99), ["color"] = new OpenApiString("#1a1a1a"), ["quantity"] = new OpenApiInteger(5), ["imagePath"] = new OpenApiString("images/exhaust.jpg"), ["carSpecificationId"] = new OpenApiInteger(1), ["partCategoryId"] = new OpenApiInteger(1), ["createdBy"] = new OpenApiInteger(1), ["createdAt"] = new OpenApiString("2024-01-15T10:30:00Z"), ["updatedAt"] = new OpenApiString("2024-01-15T10:30:00Z") };
                else if (schemaRef == nameof(FAQDto))
                    content.Value.Example = new OpenApiObject { ["id"] = new OpenApiInteger(1), ["question"] = new OpenApiString("Do you ship internationally?"), ["answer"] = new OpenApiString("Yes, we ship to most countries worldwide."), ["createdBy"] = new OpenApiInteger(1), ["createdAt"] = new OpenApiString("2024-01-15T10:30:00Z"), ["updatedAt"] = new OpenApiString("2024-01-15T10:30:00Z") };
                else if (schemaRef == nameof(OrderDto))
                    content.Value.Example = new OpenApiObject { ["id"] = new OpenApiInteger(1), ["orderDate"] = new OpenApiString("2024-01-15T10:30:00Z"), ["status"] = new OpenApiString("Pending"), ["totalPrice"] = new OpenApiDouble(4999.98), ["items"] = new OpenApiArray { new OpenApiObject { ["partId"] = new OpenApiInteger(1), ["partName"] = new OpenApiString("M Performance Exhaust"), ["quantity"] = new OpenApiInteger(2), ["unitPrice"] = new OpenApiDouble(2499.99) } }, ["createdBy"] = new OpenApiInteger(1), ["createdAt"] = new OpenApiString("2024-01-15T10:30:00Z"), ["updatedAt"] = new OpenApiString("2024-01-15T10:30:00Z") };
                else if (schemaRef == nameof(UserDto))
                    content.Value.Example = new OpenApiObject { ["id"] = new OpenApiInteger(1), ["username"] = new OpenApiString("johndoe"), ["email"] = new OpenApiString("john@example.com"), ["role"] = new OpenApiString("User"), ["createdBy"] = new OpenApiInteger(1), ["createdAt"] = new OpenApiString("2024-01-15T10:30:00Z"), ["updatedAt"] = new OpenApiString("2024-01-15T10:30:00Z") };
                else if (schemaRef == nameof(LoginResponseDto))
                    content.Value.Example = new OpenApiObject { ["accessToken"] = new OpenApiString("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."), ["refreshToken"] = new OpenApiString("dGVzdHJlZnJlc2h0b2tlbg=="), ["expiresAt"] = new OpenApiString("2024-01-15T11:30:00Z"), ["user"] = new OpenApiObject { ["id"] = new OpenApiInteger(1), ["username"] = new OpenApiString("johndoe"), ["email"] = new OpenApiString("john@example.com"), ["role"] = new OpenApiString("User") } };
                else if (schemaRef == nameof(TokenResponseDto))
                    content.Value.Example = new OpenApiObject { ["accessToken"] = new OpenApiString("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."), ["refreshToken"] = new OpenApiString("dGVzdHJlZnJlc2h0b2tlbg=="), ["expiresAt"] = new OpenApiString("2024-01-15T11:30:00Z") };

                else if (content.Value.Schema?.Type == "array")
                {
                    var itemsRef = content.Value.Schema?.Items?.Reference?.Id;
                    if (itemsRef == nameof(BrandDto))
                        content.Value.Example = new OpenApiArray { new OpenApiObject { ["id"] = new OpenApiInteger(1), ["name"] = new OpenApiString("BMW"), ["description"] = new OpenApiString("German luxury vehicles"), ["createdAt"] = new OpenApiString("2024-01-15T10:30:00Z") }, new OpenApiObject { ["id"] = new OpenApiInteger(2), ["name"] = new OpenApiString("Audi"), ["description"] = new OpenApiString("Premium German cars"), ["createdAt"] = new OpenApiString("2024-01-15T10:30:00Z") } };
                    else if (itemsRef == nameof(ModelDto))
                        content.Value.Example = new OpenApiArray { new OpenApiObject { ["id"] = new OpenApiInteger(1), ["name"] = new OpenApiString("M3"), ["brandId"] = new OpenApiInteger(1) }, new OpenApiObject { ["id"] = new OpenApiInteger(2), ["name"] = new OpenApiString("M5"), ["brandId"] = new OpenApiInteger(1) } };
                    else if (itemsRef == nameof(SpecificationDto))
                        content.Value.Example = new OpenApiArray { new OpenApiObject { ["id"] = new OpenApiInteger(1), ["modelId"] = new OpenApiInteger(1), ["volumeLitres"] = new OpenApiDouble(3.0), ["powerKilowatts"] = new OpenApiDouble(317) } };
                    else if (itemsRef == nameof(PartDto))
                        content.Value.Example = new OpenApiArray { new OpenApiObject { ["id"] = new OpenApiInteger(1), ["name"] = new OpenApiString("M Performance Exhaust"), ["price"] = new OpenApiDouble(2499.99) } };
                    else if (itemsRef == nameof(FAQDto))
                        content.Value.Example = new OpenApiArray { new OpenApiObject { ["id"] = new OpenApiInteger(1), ["question"] = new OpenApiString("Do you ship internationally?"), ["answer"] = new OpenApiString("Yes, we ship worldwide.") } };
                    else if (itemsRef == nameof(OrderDto))
                        content.Value.Example = new OpenApiArray { new OpenApiObject { ["id"] = new OpenApiInteger(1), ["orderDate"] = new OpenApiString("2024-01-15T10:30:00Z"), ["status"] = new OpenApiString("Pending"), ["totalPrice"] = new OpenApiDouble(4999.98) } };
                    else if (itemsRef == nameof(UserDto))
                        content.Value.Example = new OpenApiArray { new OpenApiObject { ["id"] = new OpenApiInteger(1), ["username"] = new OpenApiString("johndoe"), ["email"] = new OpenApiString("john@example.com"), ["role"] = new OpenApiString("User") } };
                }
            }
        }
    }

    return Task.CompletedTask;
});
});
var app = builder.Build();
if (app.Environment.IsDevelopment())
{
    app.MapOpenApi("/openapi/{documentName}.yaml");
    app.MapScalarApiReference(options =>
    {
        options.
                                WithTitle("TuningStore API").
                                WithTheme(ScalarTheme.Purple);
    });
}
*/
app.UseHttpsRedirection();
app.UseCors("AllowReactApp");
app.UseMiddleware<ErrorHandlingMiddleware>();
app.UseAuthentication();
app.UseAuthorization();
app.MapControllers();

app.Run();
