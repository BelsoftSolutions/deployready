<?php

namespace App\Http\Controllers;

use Illuminate\Http\Request;

class UserController extends Controller
{
    public function index() { return []; }
    public function show($id) { return ['id' => $id]; }
    public function store(Request $request) { return response()->json($request->all(), 201); }
}
