<?php

namespace App\Http\Controllers\Api;

use App\Models\User;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;

class AuthController extends ApiController
{

    public function register(Request $request)
    {
        $validatedData = $request->validate([
            'name' => 'required|string|max:255',
            'email' => 'required|string|email|unique:users,email',
            'password' => 'required|string|min:6|confirmed'
        ]);

        $validatedData['password'] = bcrypt($request->password);

        $user = User::create($validatedData);

        $success['token'] =  $user->createToken('token')->plainTextToken;
        $success['name'] =  $user->name;

        return $this->successResponse($success, 'User register successfully.');
    }

    public function login(Request $request)
    {
        $validatedData = $request->validate([
            'email' => 'required|string|email',
            'password' => 'required|string|min:6'
        ]);

        if(Auth::attempt($validatedData)) {
            $success['token'] = auth()->user()->createToken('token')->plainTextToken;
            $success['name'] = auth()->user()->name;
            return $this->successResponse($success, 'User login successfully.');
        }
        return $this->errorResponse('Invalid credentials !',422);
    }

    // this method signs out users by removing tokens
    public function signout()
    {
        auth()->user()->tokens()->delete();

        return [
            'message' => 'Tokens Revoked'
        ];
    }

}
