# Installation from 0
Make sure to have PHP installed (version 8.0.28 i used).

Make sure to have composer installed.

Make sure to have a relational empty database created, example with WAMP Server (phpmyAdmin, MySQL, MariaDB, etc...)

1. Clone this repository with: `composer create-project --prefer-dist laravel/laravel laravel_8_api_crud --ignore-platform-req=ext-fileinfo`

this gonna install any dependency and other process automatically, if don't, you have you create a copy of .env.example with: `cp .env.example .env` and generate an app key with: `php artisan key: generate --ansi`

2.  Into the .env file, configure de Data Base name, and string

3. Install Laravel passport: `composer require laravel/passport`, in case of error: `composer require laravel/passport --ignore-platform-req=ext-fileinfo` but this last one will update version of passport

4. After installation, then we need to migrate, but before we run our migration command, we need to specify the default string length, else, we are going to run into errors. So go to: 
```
app/Providers/AppServiceProvider.php

open the file and add this to the boot functions: 
Schema::defaultstringLength(191);

also, add this to the top of the class:
use Illuminate\Support\Facades\Schema;
```

5. Run our migration command: `php artisan migrate`

In case of error, it's propably that you have to modify php.ini file, and change:
`;extension = pdo_mysql` to `extension = pdo_mysql` and then it will be able to connect to DB

6. Create encription keys: `php artisan passport:install`
 Important: This command will also create "personal access" and "password grant" clients which will be used to generate access tokens. It will be printed on console. Save it somewhere!!

 7. Add the HasApiTokens trait to our user model:
 ```
 Go to App\Models\User.php and tell the User class to:
 `use HasApiTokens`

 Also add this to the top if HasApiTokens is not beeing called,
 `use Laravel\Passport\HasApiTokens`;
 ```

8. Call the passport routes in AuthServiceProvider
```
Go to App/Providers/AuthServiceProvider.php and add To the boot method (only if Passport version is < 11, if don't ignore this):
`Passport::routes();`

 Also add the path before the class at the top:
`use Laravel\Passport\Passport;`

Uncomment the policy in the protected method of $policies, so this line is able:
`'App\Models\Model' => 'App\Policies\ModelPolicy',`
```

9. We going to change our api driver from the default token to passport.
Go to config\auth.php and locate the guards array. In the api key, change the driver from token to passport:

```
'guards' => [
        'web' => [
            'driver' => 'session',
            'provider' => 'users',
        ],
        'api' => [
            'driver' => 'passport',
            'provider' => 'users',
            'hash' => false,
        ],
    ]
```

10. Create the Migration file for our CRUD api project: `php artisan make:model Project -m`

A migration file will be created in the database/migrations folder, and we need to create our schema, I added name (string), introduction (string), location (string), cost of the project (integer).

12. Go to app/Models/Project.php file, and add a protected method to help avoid someone hacking. Change all the content for: 

``` 
<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Model;

class Project extends Model
{
    use HasFactory;

    /**
     * The attributes that are mass assignable.
     *
     * @var array
     */
    protected $fillable = [
        'name',
        'location',
        'introduction',
        'cost',
    ];


    /**
     * The attributes that should be cast to native types.
     *
     * @var array
     */
    protected $casts = [
        'cost' => 'int',
    ];
}
```

13. Migrate the new table: `php artisan migrate`

# Create a Resource

When building an API, the response will always be in JSON format, so we need a transformation layer that sits between our Eloquent models and the JSON responses. This is what will serve the response to the application’s user in a JSON format. Laravel provides us with a resource class that will help in transforming our models and the model collections into JSON. So we are going to create that.

1. Use: `php artisan make:resource ProjectResource`

This will create a folder in the app/Http directory called Resources and also a file ProjectResource.php inside the resources.

# Create a Controller

The Controller is responsible for the direction of the flow of data and an interface between the user and the database and views. In this case, we are not interacting with views now because we are dealing with API, so our response will be in JSON format.

We are going to be creating two controllers, the first will be the Authentication Controller and the second is our Project Controller, we need the Authentication Controller in order to generate the token to use in Project Controller.

1. use: `php artisan make:controller API/AuthController`

This will create a folder called API in App/Http/Controllers. It will also create a new file called AuthController.php. 

2. Click on AuthController.php and update it with the following code:

```
<?php

namespace App\Http\Controllers\API;

use App\Http\Controllers\Controller;
use Illuminate\Http\Request;
use App\Models\User;
use Illuminate\Support\Facades\Hash;



class AuthController extends Controller
{
    public function register(Request $request)
    {
        $validatedData = $request->validate([
            'name' => 'required|max:55',
            'email' => 'email|required|unique:users',
            'password' => 'required|confirmed'
        ]);

        $validatedData['password'] = Hash::make($request->password);

        $user = User::create($validatedData);

        $accessToken = $user->createToken('authToken')->accessToken;

        return response(['user' => $user, 'access_token' => $accessToken], 201);
    }

    public function login(Request $request)
    {
        $loginData = $request->validate([
            'email' => 'email|required',
            'password' => 'required'
        ]);

        if (!auth()->attempt($loginData)) {
            return response(['message' => 'This User does not exist, check your details'], 400);
        }

        $accessToken = auth()->user()->createToken('authToken')->accessToken;

        return response(['user' => auth()->user(), 'access_token' => $accessToken]);
    }
}
```

In our AuthController, we created two methods: register and logic methods
In the register method, we use the Laravel Validate method to make sure that the name, email, and password is provided, this will also make sure that the email has not been taken and is a valid email address, the password must be confirmed before the user will be added.

After the validation, we use hash to encrypt the password before creating the user, we can't store plain password, lastly, we grab the access token and return it with the user’s information.
In the login method, we also validate the data been pass, to make sure the email and password are submitted, if the data did not correspond to any user, it will return a message that the user does not exist, if it corresponds, then it returns the user and the access token.

3. Let us create our ProjectController in the API using --api switch.

`php artisan make:controller API/ProjectController --api --model=Project`

The --api switch will create our Controller without the create and edit methods, those methods will present HTML templates.

4. Go to App/Http/Controller/API, and click on ProjectController, copy the code below and update the methods.

```
<?php

namespace App\Http\Controllers\API;

use App\Http\Controllers\Controller;
use App\Models\Project;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Validator;
use App\Http\Resources\ProjectResource;

class ProjectController extends Controller
{
    /**
     * Display a listing of the resource.
     *
     * @return \Illuminate\Http\Response
     */
    public function index()
    {
        $projects = Project::all();
        return response([ 'projects' => ProjectResource::collection($projects), 'message' => 'Retrieved successfully'], 200);
    }

    /**
     * Store a newly created resource in storage.
     *
     * @param  \Illuminate\Http\Request  $request
     * @return \Illuminate\Http\Response
     */
    public function store(Request $request)
    {
        $data = $request->all();

        $validator = Validator::make($data, [
            'name' => 'required|max:255',
            'description' => 'required|max:255',
            'cost' => 'required'
        ]);

        if ($validator->fails()) {
            return response(['error' => $validator->errors(), 'Validation Error']);
        }

        $project = Project::create($data);

        return response(['project' => new ProjectResource($project), 'message' => 'Created successfully'], 201);
    }

    /**
     * Display the specified resource.
     *
     * @param  \App\Models\Project  $project
     * @return \Illuminate\Http\Response
     */
    public function show(Project $project)
    {
        return response(['project' => new ProjectResource($project), 'message' => 'Retrieved successfully'], 200);
    }

    /**
     * Update the specified resource in storage.
     *
     * @param  \Illuminate\Http\Request  $request
     * @param  \App\Models\Project  $project
     * @return \Illuminate\Http\Response
     */
    public function update(Request $request, Project $project)
    {
        $project->update($request->all());

        return response(['project' => new ProjectResource($project), 'message' => 'Update successfully'], 200);
    }

    /**
     * Remove the specified resource from storage.
     *
     * @param  \App\Models\Project  $project
     * @return \Illuminate\Http\Response
     */
    public function destroy(Project $project)
    {
        $project->delete();

        return response(['message' => 'Deleted']);
    }
}
```

- The index method will retrieve all the projects in the database with a success message (Retrieved successfully) and returns a status code of 200.
- The store method will validate and store a new project, just like the AuthController, and returns a status code of 201, also a message of "Created successfully".
- The show method will retrieve just one project that was passed through the implicit route model binding, and also returns an HTTP code of 200 if successful.
- The update method receives the HTTP request and the particular item that needs to be edited as a parameter. It updates the project and returns the appropriate response.
- The destroy method also receives a particular project through implicit route model binding and deletes it from the database.

# Create Routes

1. Go to routes folder and click on api.php, and updates with the following code:
```
<?php

use Illuminate\Http\Request;
use Illuminate\Support\Facades\Route;
use App\Http\Controllers\API\AuthController;
use App\Http\Controllers\API\ProjectController;

/*
|--------------------------------------------------------------------------
| API Routes
|--------------------------------------------------------------------------
|
| Here is where you can register API routes for your application. These
| routes are loaded by the RouteServiceProvider within a group which
| is assigned the "api" middleware group. Enjoy building your API!
|
*/

Route::middleware('auth:api')->get('/user', function (Request $request) {
    return $request->user();
});


Route::post('register', [AuthController::class, 'register']);
Route::post('login', [AuthController::class, 'login']);

Route::apiResource('projects', ProjectController::class)->middleware('auth:api');
```

We added a register route and login routes which are post routes and also an apiResource route for projects utilizing the auth:api middleware.

# Installation from this respository

Most of the steps can be ommited, if this repository if clone from here: https://github.com/metantonio/laravel-api

I've to make a test to be sure and make a list.

# Run server

1. Run: `php artisan serve`

this will execute server at: http://127.0.0.1:8000/